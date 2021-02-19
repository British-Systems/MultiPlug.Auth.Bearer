using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using MultiPlug.Auth.Bearer.Models;
using MultiPlug.Auth.Bearer.Models.File;
using MultiPlug.Base.Security;
using Newtonsoft.Json;

namespace MultiPlug.Auth.Bearer
{
    public class BearerTokenAuthentication : IAuthentication
    {
        private static readonly string[] c_Domains = { "Token" };
        private static readonly Scheme[] c_Schemes = { Scheme.BearerToken };
        private static readonly string[] c_HttpRequestHeaders = { "Authorization" };
        private static readonly string[] c_HttpQueryKeys = { "Bearer", "Token" };

        private const string m_AuthFile = "MultiPlug.Auth.Bearer.json";

        public BearerTokenAuthentication()
        {
            if (!File.Exists(m_AuthFile))
            {
                AuthBearerFile NewFile = new AuthBearerFile
                {
                    Users = new User[]
                    {
                        new User { Enabled = false, Username = "example", Token = "ABCDEFG" }
                    }
                };

                using (StreamWriter StreamWriter = File.CreateText(m_AuthFile))
                {
                    JsonSerializer JsonSerializer = new JsonSerializer();
                    JsonSerializer.Serialize(StreamWriter, NewFile);
                }
            }
        }

        public IReadOnlyCollection<string> Domains
        {
            get
            {
                return Array.AsReadOnly(c_Domains);
            }
        }

        public IReadOnlyCollection<string> HttpRequestHeaders
        {
            get
            {
                return Array.AsReadOnly(c_HttpRequestHeaders);
            }
        }

        public IReadOnlyCollection<string> HttpQueryKeys
        {
            get
            {
                return Array.AsReadOnly(c_HttpQueryKeys);
            }
        }

        public IReadOnlyCollection<Scheme> Schemes
        {
            get
            {
                return Array.AsReadOnly(c_Schemes);
            }
        }

        public IAuthResult Authenticate(IAuthCredentials theCredentials)
        {
            AuthBearerFile AuthFileRoot = null;

            try
            {
                using (FileStream file = File.Open(m_AuthFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    using (StreamReader StreamReader = new StreamReader(file))
                    {
                        JsonSerializer serializer = new JsonSerializer();
                        AuthFileRoot = (AuthBearerFile)serializer.Deserialize(StreamReader, typeof(AuthBearerFile));
                    }
                }
            }
            catch ( InvalidOperationException ex )
            {
                return new AuthResult { Result = false, Message = "System Error: " + ex.Message};
            }
            catch ( FileNotFoundException ex )
            {
                return new AuthResult { Result = false, Message = "System Error: " + ex.Message };
            }
            catch ( Exception ex )
            {
                return new AuthResult { Result = false, Message = "System Error: " + ex.Message };
            }

            if (theCredentials.HttpRequestHeaders != null)
            {
                KeyValuePair<string, IEnumerable<string>> AuthorizationHeader = theCredentials.HttpRequestHeaders.FirstOrDefault(Header => Header.Key == c_HttpRequestHeaders[0]);

                if (AuthorizationHeader.Equals(new KeyValuePair<string, IEnumerable<string>>()))
                {
                    return new AuthResult { Result = false, Message = "Missing Authorization Header" };
                }

                if (AuthorizationHeader.Value != null && AuthorizationHeader.Value.Count() > 0)
                {
                    string Token = AuthorizationHeader.Value.First();

                    User UserSearch = AuthFileRoot.Users.FirstOrDefault(User => User.Token.Equals(Token, StringComparison.Ordinal));

                    if (UserSearch == null)
                    {
                        return new AuthResult { Result = false, Message = "Token not found" };
                    }
                    else
                    {
                        if (!UserSearch.Enabled)
                        {
                            return new AuthResult { Result = false, Message = "User is disabled" };
                        }
                        else
                        {
                            return new AuthResult { Result = true, Identity = c_Domains[0] + "\\" + UserSearch.Username, Message = string.Empty };
                        }
                    }
                }
                else
                {
                    return new AuthResult { Result = false, Message = "Missing value in Authorization Header" };
                }
            }
            else
            {
                return new AuthResult { Result = false, Message = "Missing Headers" };
            }
        }
    }
}
