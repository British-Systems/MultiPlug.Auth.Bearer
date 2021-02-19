using Newtonsoft.Json;

namespace MultiPlug.Auth.Bearer.Models.File
{
    class User
    {
        [JsonProperty("enabled", NullValueHandling = NullValueHandling.Ignore)]
        public bool Enabled { get; set; }
        [JsonProperty("username", Required = Required.Always)]
        public string Username { get; set; }
        [JsonProperty("token", Required = Required.Always)]
        public string Token { get; set; }
    }
}
