using Newtonsoft.Json;

public class Blob
{
    [JsonProperty(PropertyName = "hmac")]
    public string Hmac { get; set; }

    [JsonProperty(PropertyName = "payload")]
    public string Payload { get; set; }
}
