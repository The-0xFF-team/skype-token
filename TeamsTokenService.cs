using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json.Linq;

namespace MicrosoftTeams
{

    public class TeamsTokenService : IDisposable, IUsername, IPassword, ITokenService
    {
        private readonly HttpClient _httpClient;
        private string _password;
        private string _username;
        private readonly string _tenantId;

        private TeamsTokenService(string tenantId)
        {
            _tenantId = tenantId;
            var cookieContainer = new CookieContainer();
            using var handler = new HttpClientHandler { CookieContainer = cookieContainer };

            _httpClient = new HttpClient(handler);
        }


        public void Dispose()
        {
            _httpClient.Dispose();
        }

        public async Task<string> GetToken()
        {
            string GetFlowToken(string responseText2)
            {
                return Regex.Match(responseText2, "\"sFT\":\"([^\"]+)").Groups[1].Value;
            }

            string GetSessionId(string s1)
            {
                return Regex.Match(s1, "\"sessionId\":\"([^\"]+)").Groups[1].Value;
            }

            string GetCtx(string responseText1)
            {
                return Regex.Match(responseText1, "\"sCtx\":\"([^\"]+)").Groups[1].Value;
            }

            string GetCanary(string s)
            {
                return Regex.Match(s, "\"canary\":\"([^\"]+)").Groups[1].Value;
            }

            async Task<HttpResponseMessage> GetNecessaryTokens(HttpClient client1)
            {
                return await client1.GetAsync("https://login.microsoftonline.com/");
            }


            var user = _username;
            var password = _password;


            var cookieContainer = new CookieContainer();

            using var handler = new HttpClientHandler { CookieContainer = cookieContainer };


            using var client = new HttpClient(handler);

            client.DefaultRequestHeaders.Add("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0");


            var response = await GetNecessaryTokens(client);
            var responseText = await response.Content.ReadAsStringAsync();

            var canary = GetCanary(responseText);
            var ctx = GetCtx(responseText);
            var hpgRequestId = GetSessionId(responseText);
            var flowToken = GetFlowToken(responseText);

            var data = new Dictionary<string, string>
            {
                { "i13", "0" },
                { "login", user },
                { "loginfmt", user },
                { "type", "11" },
                { "LoginOptions", "3" },
                { "passwd", password },
                { "ps", "2" },
                { "canary", canary },
                { "ctx", ctx },
                { "hpgrequestid", hpgRequestId },
                { "flowToken", flowToken },
                { "NewUser", "1" },
                { "fspost", "0" },
                { "i21", "0" },
                { "CookieDisclosure", "0" },
                { "IsFidoSupported", "0" },
                { "isSignupPost", "0" },
                { "i2", "121" },
                { "i19", "11088" }
            };

            var loginResponse =
                await client.PostAsync("https://login.microsoftonline.com/common/login",
                    new FormUrlEncodedContent(data));
            responseText = await loginResponse.Content.ReadAsStringAsync();
            hpgRequestId = GetSessionId(responseText);

            data = new Dictionary<string, string>
            {
                { "response_type", "token" },
                { "scope", "https://api.spaces.skype.com/.default openid profile" },
                { "client_id", "5e3ce6c0-2b1f-4285-8d4b-75ee78787346" },
                { "redirect_uri", "https://teams.microsoft.com/go" },
                { "nonce", Guid.NewGuid().ToString() },
                { "client_info", "1" },
                { "x-client-SKU", "MSAL.JS" },
                { "x-client-Ver", "1.3.4" },
                { "claims", "{\"access_token\":{\"xms_cc\":{\"values\":[\"CP1\"]}}}" },
                { "login_hint", user },
                { "client-request-id", Guid.NewGuid().ToString() },
                { "prompt", "none" },
                { "response_mode", "fragment" }
            };


            client.DefaultRequestHeaders.Add("Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
            client.DefaultRequestHeaders.Add("Referer", "https://teams.microsoft.com/");
            client.DefaultRequestHeaders.Add("Accept-Encoding", "deflate, br");
            client.DefaultRequestHeaders.Add("Sec-Fetch-Dest", "iframe");
            client.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "navigate");
            client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "cross-site");
            client.DefaultRequestHeaders.Add("Origin", "https://login.microsoftonline.com");


            var uri = QueryHelpers.AddQueryString(
                $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/authorize", data);
            var oauthResponse = await client.GetAsync(uri);


            var readAsStringAsync = oauthResponse.RequestMessage.RequestUri.ToString();
            var token = Regex.Match(readAsStringAsync, "#access_token=([^&]+)").Groups[1].Value;

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            client.DefaultRequestHeaders.Add("claimsChallengeCapable", "true");
            client.DefaultRequestHeaders.Add("ms-teams-authz-type", "TokenRefresh");
            client.DefaultRequestHeaders.Remove("Referer");
            client.DefaultRequestHeaders.Add("Referer", "https://teams.microsoft.com/_");
            client.DefaultRequestHeaders.Add("X-Client-UI-Language", "en-us");
            client.DefaultRequestHeaders.Add("x-ms-client-env", "pckgsvc-prod-c1-euno-01");
            client.DefaultRequestHeaders.Add("x-ms-client-type", "web");
            client.DefaultRequestHeaders.Add("x-ms-client-version", "1415/1.0.0.2022012018");
            client.DefaultRequestHeaders.Add("x-ms-scenario-id", "59");
            client.DefaultRequestHeaders.Add("x-ms-session-id", hpgRequestId);
            client.DefaultRequestHeaders.Add("x-ms-user-type", "null");
            client.DefaultRequestHeaders.Remove("Accept");
            client.DefaultRequestHeaders.Add("Accept", "application/json, text/plain, */*");


            var authzResponse = await client.PostAsync("https://teams.microsoft.com/api/authsvc/v1.0/authz", null);
            var res = JObject.Parse(await authzResponse.Content.ReadAsStringAsync());
            
            Dispose();
            return res["tokens"]["skypeToken"].ToString();
        }

        public IUsername SetUsername(string username)
        {
            _username = username;
            return this;
        }

        public IPassword SetPassword(string password)
        {
            _password = password;
            return this;
        }
    }
}