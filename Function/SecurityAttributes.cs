namespace Function
{
    /// <summary>
    /// Apply to an Azure function to perform JWT token validation.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class AuthorizeAttribute : Attribute
    {
        /// <summary>
        /// The required scope for the token. If null or empty, no check is performed.
        /// </summary>
        public string? Scope { get; } = null;

        /// <summary>
        /// The required role for the token. If null or empty, no check is performed.
        /// </summary>
        public string? Role { get; } = null;

        public AuthorizeAttribute()
        {
        }

        public AuthorizeAttribute(string scope)
        {
            Scope = scope;
        }

        public AuthorizeAttribute(string role, string? scope = null)
        {
            Scope = scope;
            Role = role;
        }
    }
}
