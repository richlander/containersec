using System;
using System.Text;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using containersec;

public class Anchore
{

    private static string s_baseUrl = "http://localhost:8228/v1";
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
        var request = GetRequestMessage();
        request.RequestUri = new Uri($"{BaseUrl}/system");

        try
        {
            var response = await s_client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                return true;
            }

            return false;
        }
        catch (HttpRequestException)
        {
            return false;
        }
    }

    // docker-compose exec engine-api anchore-cli --u admin --p foobar image list
    // curl -u admin:foobar http://localhost:8228/v1/images
    public static async IAsyncEnumerable<ImageInfo> GetImages()
    {
        var image_detail = "image_detail";
        var tagName = "fulltag";
        var imageId = "imageId";
        var digest = "digest";
        var timestamp = "created_at";

        var request = GetRequestMessage();
        request.RequestUri = new Uri($"{BaseUrl}/images");

        var response = await s_client.SendAsync(request);

        var resultJson = await response.Content.ReadAsStringAsync();
        var resultArray = JsonConvert.DeserializeObject<object[]>(resultJson);

        foreach (JToken resultObj in resultArray)
        {
            var info = new ImageInfo();
            var detailArray = resultObj.Value<JToken>(image_detail);
            var detail = (JToken)detailArray[0];
            info.Tag = detail.Value<string>(tagName);
            info.ImageId = detail.Value<string>(imageId);
            info.Digest = detail.Value<string>(digest);
            info.TimeStamp = detail.Value<string>(timestamp);
            yield return info;
        }
    }

    private static async Task<ImageInfo> GetImageInfoForTag(string tag)
    {
        ImageInfo image = null;
        await foreach (var i in GetImages())
        {
            if (i.Tag == tag)
            {
                image = i;
                break;
            }
        }

        return image;
    }

    // docker-compose exec engine-api anchore-cli --u admin --p foobar image vuln microsoft/dotnet:2.2-sdk all
    // curl -u admin:foobar http://localhost:8228/v1/images/sha256:a0f63e884cec2505b0ae505e1c314be4c5b4071868b8ad3cd36d0ab414df3ae5/vuln/all
    public static async Task<List<Vulnerability>> GetVulnerabilitiesForImage(string tag)
    {

        var image = await GetImageInfoForTag(tag);

        var request = GetRequestMessage();
        request.RequestUri = new Uri($"{BaseUrl}/images/{image.Digest}/vuln/all");

        var response = await s_client.SendAsync(request);
        var resultJson = await response.Content.ReadAsStringAsync();
        var resultObj = JsonConvert.DeserializeObject<JToken>(resultJson);
        var vulnArray = resultObj.Value<JArray>("vulnerabilities");
        var vulnerabilities = vulnArray.ToObject<List<Vulnerability>>();
        return vulnerabilities;
    }

    // docker-compose exec engine-api anchore-cli --u admin --p foobar image add microsoft/dotnet:2.2-sdk
    // curl -XPOST -H "content-type: application/json" -u admin:foobar http://localhost:8228/v1/images -d"@/root/imageadd_bydigest.json"
    /* # cat /root/imageadd_bydigest.json
    {
    "digest": "sha256:0873c923e00e0fd2ba78041bfb64a105e1ecb7678916d1f7776311e45bf5634b",
    "image_type": "docker",
    "tag": "docker.io/alpine:latest",
    "created_at": "2018-11-01T00:33:42Z"
    }
    */
    public static async Task<bool> RegisterImage(ImageInfo image)
    {
        var request = GetRequestMessage();
        request.Method = HttpMethod.Post;
        var json = JsonConvert.SerializeObject(image);
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

namespace System.Collections.Generic
{
    public interface IAsyncEnumerable<out T>
    {
        IAsyncEnumerator<T> GetAsyncEnumerator();
    }

    public interface IAsyncEnumerator<out T> : System.IAsyncDisposable
    {
        System.Threading.Tasks.ValueTask<bool> MoveNextAsync();
        T Current { get; }
    }
}
