using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using System.Net;

namespace Function
{
    public class Function1
    {
        private readonly ILogger<Function1> _logger;

        public Function1(ILogger<Function1> logger)
        {
            _logger = logger;
        }

        [Authorize] // Token validation without checking for a certain scope or role.
        // [Authorize(scope:"my.scope")] // Token validation with a required scope.
        // [Authorize(role:"my.role")] // Token validation with a required role.
        [Function("Function1")]
        public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData req, FunctionContext context)
        {
            if (!TokenValidationMiddleware.IsAuthenticated(context, out var unathenticatedResponse))
            {
                // Middleware cannot return early.
                // The function needs to check if the middleware set an unathenticated response and if so return the 401.
                return unathenticatedResponse;
            }

            _logger.LogInformation("C# HTTP trigger function processed a request.");
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/json; charset=utf-8");
            response.WriteString("Hello, from Function1.");
            return response;
        }
    }
}
