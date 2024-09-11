namespace KeyCloakAuthenticationApp.Configuration
{
    public class KeycloakSettings
    {
        public string Audience { get; set; }
        public string ValidIssuer { get; set; }
        public string MetadataAddress { get; set; }
        public string AuthorizationUrl { get; set; }
        public bool RequireHttpsMetadata { get; set; }
}
}
