# JWT Validation Middleware for Azure Functions (Isolated Worker Model)

This sample implements JWT token validation middleware for Azure function isolated worker functions.
* Each function can choose to be authorized or not, and optionally, specify a required scope or role.
* Function validation with Function codes still works the same.

I find Azure EzAuth pretty crappy due to generally bad visibility and logging as well as lack of customization and flexibility. This is an alternative that moves validation in house and lets you decorate your functions independently.

Please test throughougly for your use case before using in a production system!

# Sample

```c#
        [Authorize] // Token validation without checking for a certain scope or role.
        // [Authorize(scope:"my.scope")] // Token validation with a required scope.
        // [Authorize(role:"my.role")] // Token validation with a required role.
        [Function("Function1")]
        public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get")]
            HttpRequestData req, FunctionContext context)
        {
            if (!TokenValidationMiddleware.IsAuthenticated(context, out var unathenticatedResponse))
            {
                // Middleware cannot return early. So the function should return a 401 if validation failed.
                return unathenticatedResponse;
            }

            _logger.LogInformation("C# HTTP trigger function processed a request.");
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/json; charset=utf-8");
            response.WriteString("Hello, from Function1.");
            return response;
        }
```
