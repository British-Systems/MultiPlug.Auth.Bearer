using System;
using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Bearer.Models
{
    class AuthResult : IAuthResult
    {
        public string Identity { get; set; }
        public string Message { get; set; }
        public bool Result { get; set; }
    }
}
