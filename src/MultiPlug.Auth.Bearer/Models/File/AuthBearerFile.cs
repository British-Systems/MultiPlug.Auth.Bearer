using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MultiPlug.Auth.Bearer.Models.File
{
    class AuthBearerFile
    {
        [JsonProperty("users", Required = Required.Always)]
        public User[] Users { get; set; }
    }
}
