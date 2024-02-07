namespace Function
{
    internal static class SecurityConfig
    {
        // Set appropriately for you app. Considering moving into configuration.
        internal static string[] ValidIssuers = ["valid-issuer"];
        internal static string[] ValidAudiences = ["valid-audience"];
        internal static string OpenIdConnectConfigurationUrl = "https://<your-sign-in-provider>/v2.0/.well-known/openid-configuration";
    }
}
