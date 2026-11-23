using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

// ---------- Configuração SÓ por variáveis de ambiente (nada de senha no código) ----------
static string Env(string k, string? d = null) =>
    Environment.GetEnvironmentVariable(k) ?? d
    ?? throw new InvalidOperationException($"Variável de ambiente ausente: {k}");

var connStr = new NpgsqlConnectionStringBuilder
{
    Host = Env("DB_HOST"), Port = int.Parse(Env("DB_PORT")), Database = Env("DB_NAME"),
    Username = Env("DB_USER"), Password = Env("DB_PASSWORD"),
}.ConnectionString;

var jwtKey = Env("JWT_KEY");
if (jwtKey.Length < 32) throw new InvalidOperationException("JWT_KEY precisa ter 32+ caracteres.");
var keyBytes = Encoding.UTF8.GetBytes(jwtKey);
var encKey = Env("DB_ENC_KEY");   // chave do pgcrypto: só em variável de ambiente, nunca no banco
if (encKey.Length < 32) throw new InvalidOperationException("DB_ENC_KEY precisa ter 32+ caracteres.");
var maxAgeDays = int.Parse(Env("PASSWORD_MAX_AGE_DAYS", "90"));

const int MaxFalhas = 5;          // tentativas erradas até bloquear
const int BloqueioMin = 15;       // minutos de bloqueio
const int BcryptCost = 12;        // custo do BCrypt (2^12 rodadas)

builder.Services.AddSingleton(NpgsqlDataSource.Create(connStr));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
    o.MapInboundClaims = false;   // mantém os nomes originais das claims ("sub", "perfil")
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false, ValidateAudience = false,
        ValidateLifetime = true, ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ClockSkew = TimeSpan.Zero,
    };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// Hash "falso" usado para gastar o mesmo tempo quando o e-mail não existe
// (evita descobrir quais e-mails estão cadastrados medindo o tempo de resposta).
var hashFalso = BCrypt.Net.BCrypt.HashPassword("senha-falsa-para-timing", BcryptCost);

// ---------- Regras de senha forte ----------
static string? ValidarSenha(string? s)
{
    if (string.IsNullOrEmpty(s) || s.Length < 10) return "A senha precisa ter pelo menos 10 caracteres.";
    if (!s.Any(char.IsUpper)) return "A senha precisa ter letra maiúscula.";
    if (!s.Any(char.IsLower)) return "A senha precisa ter letra minúscula.";
    if (!s.Any(char.IsDigit)) return "A senha precisa ter número.";
    if (!s.Any(c => !char.IsLetterOrDigit(c))) return "A senha precisa ter caractere especial (ex.: ! @ # $).";
    return null;
}
static string Sha256Hex(string t) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(t)));
static string Norm(string? e) => (e ?? "").Trim().ToLowerInvariant();

string GerarJwt(Guid id, string perfil) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
{
    Subject = new ClaimsIdentity(new[] { new Claim("sub", id.ToString()), new Claim("perfil", perfil) }),
    Expires = DateTime.UtcNow.AddMinutes(15),
    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256),
});

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// ---------- Cadastro ----------
app.MapPost("/auth/register", async (RegisterReq r, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    var email = Norm(r.Email);
    if (!email.Contains('@')) return Results.BadRequest(new { erro = "E-mail inválido." });
    if (r.Perfil is not ("Responsavel" or "Terapeuta")) return Results.BadRequest(new { erro = "Perfil inválido." });
    var erroSenha = ValidarSenha(r.Senha);
    if (erroSenha != null) return Results.BadRequest(new { erro = erroSenha });

    var hash = BCrypt.Net.BCrypt.HashPassword(r.Senha, BcryptCost);
    try
    {
        await using var cmd = ds.CreateCommand(
            "insert into usuario(email, senha_hash, perfil) values (@e, @h, @p)");
        cmd.Parameters.AddWithValue("e", email);
        cmd.Parameters.AddWithValue("h", hash);
        cmd.Parameters.AddWithValue("p", r.Perfil);
        await cmd.ExecuteNonQueryAsync();
    }
    catch (PostgresException ex) when (ex.SqlState == "23505")
    {
        return Results.Json(new { erro = "E-mail já cadastrado." }, statusCode: 409);
    }
    log.LogInformation("AUDIT cadastro perfil={Perfil}", r.Perfil);
    return Results.Created("/me", new { mensagem = "Cadastro realizado." });
});

// ---------- Login ----------
app.MapPost("/auth/login", async (LoginReq r, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    var email = Norm(r.Email);
    Guid id = default; string? hash = null, perfil = null; bool bloqueado = false, expirada = false;

    await using (var cmd = ds.CreateCommand(@"
        select id, senha_hash, perfil,
               (bloqueado_ate is not null and bloqueado_ate > now()),
               (senha_alterada_em < now() - make_interval(days => @d))
        from usuario where email = @e"))
    {
        cmd.Parameters.AddWithValue("e", email);
        cmd.Parameters.AddWithValue("d", maxAgeDays);
        await using var rd = await cmd.ExecuteReaderAsync();
        if (await rd.ReadAsync())
        {
            id = rd.GetGuid(0); hash = rd.GetString(1); perfil = rd.GetString(2);
            bloqueado = rd.GetBoolean(3); expirada = rd.GetBoolean(4);
        }
    }

    if (hash == null)
    {
        BCrypt.Net.BCrypt.Verify(r.Senha ?? "", hashFalso);
        log.LogWarning("AUDIT login_falhou motivo=usuario_inexistente");
        return Results.Json(new { erro = "E-mail ou senha incorretos." }, statusCode: 401);
    }
    if (bloqueado)
    {
        log.LogWarning("AUDIT login_bloqueado usuario={Id}", id);
        return Results.Json(new { erro = $"Conta bloqueada por {BloqueioMin} minutos após várias tentativas." }, statusCode: 429);
    }
    if (!BCrypt.Net.BCrypt.Verify(r.Senha ?? "", hash))
    {
        await using var up = ds.CreateCommand(@"
            update usuario set
              tentativas_falhas = case when tentativas_falhas + 1 >= @max then 0 else tentativas_falhas + 1 end,
              bloqueado_ate = case when tentativas_falhas + 1 >= @max
                                   then now() + make_interval(mins => @min) else bloqueado_ate end
            where id = @id");
        up.Parameters.AddWithValue("max", MaxFalhas);
        up.Parameters.AddWithValue("min", BloqueioMin);
        up.Parameters.AddWithValue("id", id);
        await up.ExecuteNonQueryAsync();
        log.LogWarning("AUDIT login_falhou motivo=senha_errada usuario={Id}", id);
        return Results.Json(new { erro = "E-mail ou senha incorretos." }, statusCode: 401);
    }

    await using (var ok = ds.CreateCommand("update usuario set tentativas_falhas = 0, bloqueado_ate = null where id = @id"))
    {
        ok.Parameters.AddWithValue("id", id);
        await ok.ExecuteNonQueryAsync();
    }
    if (expirada)
    {
        log.LogInformation("AUDIT login_senha_expirada usuario={Id}", id);
        return Results.Json(new { codigo = "SENHA_EXPIRADA", erro = $"Sua senha tem mais de {maxAgeDays} dias. Troque-a para continuar." }, statusCode: 403);
    }
    log.LogInformation("AUDIT login_ok usuario={Id}", id);
    return Results.Ok(new { token = GerarJwt(id, perfil!), perfil, expiraEmMin = 15 });
});

// ---------- Troca de senha (usada também na troca obrigatória) ----------
app.MapPost("/auth/trocar-senha", async (TrocarReq r, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    var erroSenha = ValidarSenha(r.NovaSenha);
    if (erroSenha != null) return Results.BadRequest(new { erro = erroSenha });

    Guid id = default; string? hash = null;
    await using (var cmd = ds.CreateCommand("select id, senha_hash from usuario where email = @e"))
    {
        cmd.Parameters.AddWithValue("e", Norm(r.Email));
        await using var rd = await cmd.ExecuteReaderAsync();
        if (await rd.ReadAsync()) { id = rd.GetGuid(0); hash = rd.GetString(1); }
    }
    if (hash == null || !BCrypt.Net.BCrypt.Verify(r.SenhaAtual ?? "", hash))
        return Results.Json(new { erro = "E-mail ou senha atual incorretos." }, statusCode: 401);
    if (BCrypt.Net.BCrypt.Verify(r.NovaSenha, hash))
        return Results.BadRequest(new { erro = "A nova senha deve ser diferente da atual." });

    await using var up = ds.CreateCommand(
        "update usuario set senha_hash = @h, senha_alterada_em = now() where id = @id");
    up.Parameters.AddWithValue("h", BCrypt.Net.BCrypt.HashPassword(r.NovaSenha, BcryptCost));
    up.Parameters.AddWithValue("id", id);
    await up.ExecuteNonQueryAsync();
    log.LogInformation("AUDIT senha_trocada usuario={Id}", id);
    return Results.Ok(new { mensagem = "Senha alterada. Faça login novamente." });
});

// ---------- Esqueci a senha ----------
app.MapPost("/auth/esqueci-senha", async (EsqueciReq r, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    Guid? id = null;
    await using (var cmd = ds.CreateCommand("select id from usuario where email = @e"))
    {
        cmd.Parameters.AddWithValue("e", Norm(r.Email));
        var o = await cmd.ExecuteScalarAsync();
        if (o is Guid g) id = g;
    }
    if (id != null)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        await using var ins = ds.CreateCommand(@"
            insert into reset_senha(usuario_id, token_hash, expira_em)
            values (@u, @t, now() + interval '30 minutes')");
        ins.Parameters.AddWithValue("u", id.Value);
        ins.Parameters.AddWithValue("t", Sha256Hex(token));   // só o hash vai pro banco
        await ins.ExecuteNonQueryAsync();
        // DESENVOLVIMENTO: sem servidor de e-mail ainda, o token aparece no log da API.
        // Em produção este trecho é trocado por envio de e-mail (SMTP) e o log é removido.
        log.LogWarning("DEV-ONLY token de redefinição (valido por 30 min): {Token}", token);
        log.LogInformation("AUDIT reset_solicitado usuario={Id}", id);
    }
    // Resposta idêntica exista o e-mail ou não (não revela quem tem conta).
    return Results.Ok(new { mensagem = "Se o e-mail existir, enviaremos as instruções de redefinição." });
});

app.MapPost("/auth/redefinir-senha", async (RedefinirReq r, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    var erroSenha = ValidarSenha(r.NovaSenha);
    if (erroSenha != null) return Results.BadRequest(new { erro = erroSenha });

    await using var conn = await ds.OpenConnectionAsync();
    await using var tx = await conn.BeginTransactionAsync();

    Guid resetId = default, userId = default; bool achou = false;
    await using (var sel = new NpgsqlCommand(@"
        select id, usuario_id from reset_senha
        where token_hash = @t and not usado and expira_em > now() for update", conn, tx))
    {
        sel.Parameters.AddWithValue("t", Sha256Hex(r.Token ?? ""));
        await using var rd = await sel.ExecuteReaderAsync();
        if (await rd.ReadAsync()) { resetId = rd.GetGuid(0); userId = rd.GetGuid(1); achou = true; }
    }
    if (!achou) return Results.BadRequest(new { erro = "Código inválido ou expirado." });

    await using (var up = new NpgsqlCommand(@"
        update usuario set senha_hash = @h, senha_alterada_em = now(),
                           tentativas_falhas = 0, bloqueado_ate = null where id = @u", conn, tx))
    {
        up.Parameters.AddWithValue("h", BCrypt.Net.BCrypt.HashPassword(r.NovaSenha, BcryptCost));
        up.Parameters.AddWithValue("u", userId);
        await up.ExecuteNonQueryAsync();
    }
    await using (var us = new NpgsqlCommand("update reset_senha set usado = true where id = @i", conn, tx))
    {
        us.Parameters.AddWithValue("i", resetId);
        await us.ExecuteNonQueryAsync();
    }
    await tx.CommitAsync();
    log.LogInformation("AUDIT senha_redefinida usuario={Id}", userId);
    return Results.Ok(new { mensagem = "Senha redefinida. Faça login." });
});


// ---------- Crianças e emoções (emoção CRIPTOGRAFADA com pgcrypto) ----------
string[] emocoesValidas = { "Feliz", "Calmo", "Triste", "Bravo", "Ansioso", "Cansado" };
static Guid IdDe(ClaimsPrincipal u) => Guid.Parse(u.FindFirst("sub")!.Value);

// Só o terapeuta dono do cadastro enxerga a criança (evita acesso a dados de outras)
static async Task<bool> EhDono(NpgsqlDataSource ds, Guid crianca, ClaimsPrincipal u)
{
    await using var cmd = ds.CreateCommand("select 1 from crianca where id = @c and terapeuta_id = @t");
    cmd.Parameters.AddWithValue("c", crianca);
    cmd.Parameters.AddWithValue("t", IdDe(u));
    return await cmd.ExecuteScalarAsync() != null;
}

app.MapPost("/criancas", async (CriancaReq r, ClaimsPrincipal u, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    if (u.FindFirst("perfil")?.Value != "Terapeuta")
        return Results.Json(new { erro = "Apenas a terapeuta cadastra crianças." }, statusCode: 403);
    if (string.IsNullOrWhiteSpace(r.Nome)) return Results.BadRequest(new { erro = "Nome obrigatório." });
    await using var cmd = ds.CreateCommand("insert into crianca(terapeuta_id, nome) values (@t, @n) returning id");
    cmd.Parameters.AddWithValue("t", IdDe(u));
    cmd.Parameters.AddWithValue("n", r.Nome.Trim());
    var id = (Guid)(await cmd.ExecuteScalarAsync())!;
    log.LogInformation("AUDIT crianca_criada id={Id}", id);
    return Results.Created($"/criancas/{id}", new { id, nome = r.Nome.Trim() });
}).RequireAuthorization();

// Busca por nome: URL com parâmetro (alvo do SQLMap). Consulta parametrizada.
app.MapGet("/criancas", async (string? nome, ClaimsPrincipal u, NpgsqlDataSource ds) =>
{
    await using var cmd = ds.CreateCommand(
        "select id, nome from crianca where terapeuta_id = @t and nome ilike @n order by nome");
    cmd.Parameters.AddWithValue("t", IdDe(u));
    cmd.Parameters.AddWithValue("n", "%" + (nome ?? "") + "%");
    var lista = new List<object>();
    await using var rd = await cmd.ExecuteReaderAsync();
    while (await rd.ReadAsync()) lista.Add(new { id = rd.GetGuid(0), nome = rd.GetString(1) });
    return Results.Ok(lista);
}).RequireAuthorization();

app.MapPost("/criancas/{id:guid}/emocoes", async (Guid id, EmocaoReq r, ClaimsPrincipal u, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    if (!emocoesValidas.Contains(r.Emocao ?? ""))
        return Results.BadRequest(new { erro = "Emoção inválida.", validas = emocoesValidas });
    if (!await EhDono(ds, id, u)) return Results.Json(new { erro = "Criança não encontrada." }, statusCode: 404);
    await using var cmd = ds.CreateCommand(
        "insert into registro_emocional(crianca_id, emocao) values (@c, pgp_sym_encrypt(@e, @k))");
    cmd.Parameters.AddWithValue("c", id);
    cmd.Parameters.AddWithValue("e", r.Emocao!);
    cmd.Parameters.AddWithValue("k", encKey);
    await cmd.ExecuteNonQueryAsync();
    log.LogInformation("AUDIT emocao_registrada crianca={Id}", id);
    return Results.Created($"/criancas/{id}/emocoes", new { mensagem = "Emoção registrada." });
}).RequireAuthorization();

app.MapGet("/criancas/{id:guid}/emocoes", async (Guid id, ClaimsPrincipal u, NpgsqlDataSource ds, ILogger<Program> log) =>
{
    if (!await EhDono(ds, id, u)) return Results.Json(new { erro = "Criança não encontrada." }, statusCode: 404);
    await using var cmd = ds.CreateCommand(@"
        select pgp_sym_decrypt(emocao, @k), registrado_em
        from registro_emocional where crianca_id = @c order by registrado_em desc limit 100");
    cmd.Parameters.AddWithValue("c", id);
    cmd.Parameters.AddWithValue("k", encKey);
    var lista = new List<object>();
    await using var rd = await cmd.ExecuteReaderAsync();
    while (await rd.ReadAsync()) lista.Add(new { emocao = rd.GetString(0), registradoEm = rd.GetFieldValue<DateTime>(1) });
    log.LogInformation("AUDIT emocoes_lidas crianca={Id}", id);   // leitura de dado sensível fica registrada
    return Results.Ok(lista);
}).RequireAuthorization();

// ---------- Rota protegida de exemplo ----------
app.MapGet("/me", (ClaimsPrincipal u) => Results.Ok(new
{
    id = u.FindFirst("sub")?.Value,
    perfil = u.FindFirst("perfil")?.Value,
})).RequireAuthorization();

app.Run();

record RegisterReq(string? Email, string? Senha, string? Perfil);
record LoginReq(string? Email, string? Senha);
record TrocarReq(string? Email, string? SenhaAtual, string? NovaSenha);
record EsqueciReq(string? Email);
record RedefinirReq(string? Token, string? NovaSenha);
record CriancaReq(string? Nome);
record EmocaoReq(string? Emocao);
