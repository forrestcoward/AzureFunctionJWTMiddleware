using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Reflection;
using System.Security.Claims;

namespace Function
{
    /// <summary>
    /// Implements JWT validation as Azure function middleware.
    /// Token validation happens with System.IdentityModel.Tokens.Jwt assembly.
    /// 
    /// The middleware looks for the presence of the [Authorize('scope', 'role')] attribute on the calling Azure function.
    /// If not present, authorization is granted.
    /// If present, the bearer token passed in the Authorization header is validated as a JWT token with the required scope and role.
    /// 
    /// If authorization fails, then the following is set as an Anuthorized result:
    /// context.Items["HttpResponseData"]
    /// Azure functions must check for the presence of "HttpResponseData" and return it as the result if it exists.
    /// Unfortunately middleware cannot return the final API response directly.
    /// </summary>
    public class TokenValidationMiddleware : IFunctionsWorkerMiddleware
    {
        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            var httpRequest = await context.GetHttpRequestDataAsync();

            if (httpRequest == null)
            {
                // Not an HTTP trigger.
                await next(context);
                return;
            }

            var logger = context.GetLogger<TokenValidationMiddleware>();
            logger.LogInformation("Authorizing request...");

            // Check if the Authenticate attribute is present.
            var authorizeAttribute = GetTargetFunctionMethod(context).GetCustomAttributes(typeof(AuthorizeAttribute), false).FirstOrDefault() as AuthorizeAttribute;
            var shouldAuthorize = authorizeAttribute != null;

            var authorized = false;
            if (!shouldAuthorize)
            {
                logger.LogInformation($"No AuthorizeAttribute found on function.");
                authorized = true;
            }

            if (shouldAuthorize)
            {
                if (httpRequest.Headers.TryGetValues("Authorization", out var values))
                {
                    var token = values.First().Split(" ").Last();
                    var authenticated = ValidateToken(token, out var principal, logger);

                    if (authenticated && principal != null)
                    {
                        var requiredScope = authorizeAttribute.Scope;
                        var requiredRole = authorizeAttribute.Role;

                        if (string.IsNullOrWhiteSpace(requiredScope) && string.IsNullOrWhiteSpace(requiredRole))
                        {
                            authorized = true;
                        }

                        if (!string.IsNullOrWhiteSpace(requiredScope))
                        {
                            authorized = HasRequiredScope(principal, requiredScope, logger);
                        }

                        if (!string.IsNullOrWhiteSpace(requiredRole))
                        {
                            authorized &= HasRequiredRole(principal, requiredRole, logger);
                        }
                    }
                    else
                    {
                        logger.LogInformation($"JWT token validation failed.");
                    }
                }
                else
                {
                    logger.LogInformation($"Missing authorization token on request.");
                }
            }

            if (!authorized)
            {
                logger.LogInformation("Authorization failed!");
                context.Items["HttpResponseData"] = await CreateUnauthorizedResponse(httpRequest);
            }
            else
            {
                logger.LogInformation("Request authorized.");
            }

            await next(context);
        }

        private static bool ValidateToken(string token, out ClaimsPrincipal? principal, ILogger logger)
        {
            principal = null;
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters();

            try
            {
                principal = handler.ValidateToken(token, validationParameters, out var validatedToken);
                // ValidateToken is a success if no exception is thrown.
                return true;
            }
            catch (SecurityTokenException se)
            {
                logger.LogError($"[Authentication failed] Token validation failed: {se.Message}");
                return false;
            }
            catch (Exception ex)
            {
                logger.LogError($"[Authentication failed] Unexpected error during token validation: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Determines if the FunctionContext is authorized.
        /// </summary>
        /// <param name="context">the function context</param>
        /// <param name="response">the response to send if unathorized</param>
        /// <returns>true if authorized, false otherwise</returns>
        public static bool IsAuthenticated(FunctionContext context, out HttpResponseData? response)
        {
            response = null;
            if (context.Items.TryGetValue("HttpResponseData", out var httpResponseObj) && httpResponseObj is HttpResponseData httpResponse)
            {
                response = httpResponse;
                return false;
            }

            return true;
        }

        private static bool HasRequiredScope(ClaimsPrincipal principal, string requiredScope, ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(principal);
            ArgumentException.ThrowIfNullOrWhiteSpace(requiredScope);

            var scopeClaim = principal.Claims.FirstOrDefault(c => c.Type == "scp" || c.Type == "http://schemas.microsoft.com/identity/claims/scope");
            var scopes = scopeClaim?.Value.Split(' ') ?? [];

            if (!scopes.Contains(requiredScope))
            {
                logger.LogError($"[Authorization failed] Required scope '{requiredScope}' not found in token.");
                return false;
            }

            return true;
        }

        private static bool HasRequiredRole(ClaimsPrincipal principal, string requiredRole, ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(principal);
            ArgumentException.ThrowIfNullOrWhiteSpace(requiredRole);

            var rolesClaim = principal.Claims.FirstOrDefault(c => c.Type == "roles");
            var roles = rolesClaim?.Value.Split(' ') ?? [];

            if (!roles.Contains(requiredRole))
            {
                logger.LogError($"[Authorization failed] Required role '{requiredRole}' not found in token.");
                return false;
            }

            return true;
        }

        private async Task<HttpResponseData> CreateUnauthorizedResponse(Microsoft.Azure.Functions.Worker.Http.HttpRequestData request)
        {
            ArgumentNullException.ThrowIfNull(request);

            var response = request.CreateResponse(HttpStatusCode.Unauthorized);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");
            await response.WriteStringAsync("Unauthorized");
            return response;
        }

        private static TokenValidationParameters GetValidationParameters()
        {
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                SecurityConfig.OpenIdConnectConfigurationUrl,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());

            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = SecurityConfig.ValidIssuers,
                ValidateAudience = true,
                ValidAudiences = SecurityConfig.ValidAudiences,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5),
                ValidateActor = false,
                IssuerSigningKeyResolver = (token, securityToken, identifier, parameters) =>
                {
                    // Retrieve the Azure AD signing keys to validate the token.
                    var config = configurationManager.GetConfigurationAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                    return config.SigningKeys;
                }
            };
        }

        // Use reflection to get the underlying function of the Azure function (which can be used to retrieve the attributes).
        private static MethodInfo GetTargetFunctionMethod(FunctionContext context)
        {
            var assemblyPath = context.FunctionDefinition.PathToAssembly;
            var assembly = Assembly.LoadFrom(assemblyPath);
            var typeName = context.FunctionDefinition.EntryPoint.Substring(0, context.FunctionDefinition.EntryPoint.LastIndexOf('.'));
            var type = assembly.GetType(typeName);
            var methodName = context.FunctionDefinition.EntryPoint.Substring(context.FunctionDefinition.EntryPoint.LastIndexOf('.') + 1);
            var method = type.GetMethod(methodName);
            return method;
        }
    }
}
