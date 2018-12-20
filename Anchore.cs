using System;
using System.Text;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class Anchore
{

    private static string s_baseUrl = "http://localhost:8227/v1";
    private static HttpClient s_client = new HttpClient();

    public static string BaseUrl
    {
        get
        {
            return s_baseUrl;
        }
        set
        {
            s_baseUrl = value;
        }
    }

    public static async Task<bool> CheckStatus()
    {
        var message = GetRequestMessage();
        message.RequestUri = new Uri($"{BaseUrl}/system");

        try
        {
            var response = await s_client.SendAsync(message);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    public static async Task<bool> RegisterImage(string tag)
    {
        var request = GetRequestMessage();
        request.Method = HttpMethod.Post;
        var token = new DigestInfo();
        token.tag = tag;
        var json = JsonConvert.SerializeObject(token);
        var content = new StringContent(json);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Content = content;
        var client = new HttpClient();
        var result = await client.SendAsync(request);
        var resultJson = await result.Content.ReadAsStringAsync();
        var resultArray = JsonConvert.DeserializeObject<object[]>(resultJson);
        var resultObj = (JToken)resultArray[0];
        var analyzed = resultObj.Value<string>("analysis_status");

        return (analyzed == "analyzed");
    }


    private static HttpRequestMessage GetRequestMessage()
    {
        var request = new HttpRequestMessage();
        request.Method = HttpMethod.Get;
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:foobar")));
        return request;
    }

}