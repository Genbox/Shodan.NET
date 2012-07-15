using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Script.Serialization;
using System.Globalization;

namespace Shodan
{
    public class Shodan
    {
        private const string BaseUrl = "http://beta.shodanhq.com/api/";
        private readonly string _apiKey;
        private JavaScriptSerializer _jsonParser = new JavaScriptSerializer();
        private WebClient _webClient = new WebClient();

        public Shodan(string apiKey)
        {
            _apiKey = apiKey;
        }

        /// <summary>
        ///  Get all the information Shodan has on the IP.
        /// </summary>
        /// <param name="ip">IP of the computer to look up</param>
        /// <returns>A Host object with the banners and location information.</returns>
        public Host GetHost(IPAddress ip)
        {
            string strIp = ip.ToString();

            // Send the request
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["ip"] = strIp;
            Dictionary<string, object> resDict = SendRequest("host", args);

            Host host = new Host(resDict);
            return host;
        }

        /// <summary>
        ///  Get all the information Shodan has on the IP (given as a string).
        /// </summary>
        /// <param name="ip">IP of the computer to look up</param>
        /// <returns>A Host object with the banners and location information.</returns>
        public Host GetHost(string ip)
        {
            return GetHost(IPAddress.Parse(ip));
        }

        /// <summary>
        ///  Search the Shodan search engine for computers matching the given search criteria.
        /// </summary>
        /// <param name="query">The search query for Shodan; identical syntax to the website. </param>
        /// <param name="offset">The starting position for the search cursor.</param>
        /// <param name="limit">The number of hosts to return per search query.</param>
        /// <returns> A SearchResult object that contains a List of Hosts matching the query and the total number of results found. </returns>
        public List<Host> Search(string query, int offset = 0, int limit = 100)
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["q"] = query;
            args["o"] = offset.ToString();
            args["l"] = limit.ToString();
            Dictionary<string, object> resDict = SendRequest("search", args);

            List<Host> hosts = new List<Host>(resDict.Count);

            ArrayList arrayList = (ArrayList)resDict["matches"];
            foreach (Dictionary<string, object> item in arrayList)
            {
                hosts.Add(new Host(item, true));
            }

            return hosts;
        }

        public List<Exploit> SearchExploits(string query, string author = "", string platform = "", int port = 0, string type = "")
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["q"] = query;

            if (!string.IsNullOrEmpty(author))
                args["author"] = author;

            if (!string.IsNullOrEmpty(platform))
                args["platform"] = platform;

            if (port >= 1)
                args["port"] = port.ToString();

            if (!string.IsNullOrEmpty(type))
                args["type"] = type;

            Dictionary<string, object> resDict = SendRequest("exploitdb/search", args);
            List<Exploit> exploits = new List<Exploit>(resDict.Count);

            ArrayList arrayList = (ArrayList)resDict["matches"];
            foreach (Dictionary<string, object> item in arrayList)
            {
                exploits.Add(new Exploit(item));
            }

            return exploits;
        }

        public DataResponse DownloadExploit(int id)
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["id"] = id.ToString();
            Dictionary<string, object> resDict = SendRequest("exploitdb/download", args);

            DataResponse exploit = new DataResponse(resDict);
            return exploit;
        }

        public List<MSFModule> SearchMSFModules(string query)
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["q"] = query;

            Dictionary<string, object> resDict = SendRequest("msf/search", args);
            List<MSFModule> modules = new List<MSFModule>(resDict.Count);

            ArrayList arrayList = (ArrayList)resDict["matches"];
            foreach (Dictionary<string, object> item in arrayList)
            {
                modules.Add(new MSFModule(item));
            }

            return modules;
        }

        public DataResponse DownloadMSFModule(string id)
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            args["id"] = id;
            Dictionary<string, object> resDict = SendRequest("msf/download", args);

            DataResponse module = new DataResponse(resDict);
            return module;
        }

        /// <summary>
        ///  Internal wrapper function to send API requests.
        /// </summary>
        /// <param name="apiFunc">The API function to call.</param>
        /// <param name="args">The arguments to pass to the given API function.</param>
        private Dictionary<string, object> SendRequest(string apiFunc, Dictionary<string, string> args)
        {
            // Convert the arguments to a query string
            string strArgs = ToQuerystring(args);

            // Send the request
            Stream response = _webClient.OpenRead(BaseUrl + apiFunc + strArgs + "&key=" + _apiKey);

            // Read the response into a string
            StreamReader reader = new StreamReader(response);
            string data = reader.ReadToEnd();
            reader.Close();

            // Turn the JSON string into a native dictionary object
            Dictionary<string, object> result = _jsonParser.Deserialize<Dictionary<string, object>>(data);

            // Raise an exception if an error was returned
            if (result.ContainsKey("error"))
                throw new ArgumentException((string)result["error"]);

            return result;
        }

        private string ToQuerystring(Dictionary<string, string> dict)
        {
            return "?" + string.Join("&", dict.Select(x => string.Format("{0}={1}", HttpUtility.UrlEncode(x.Key), HttpUtility.UrlEncode(x.Value))));
        }
    }

    public class Exploit
    {
        public Exploit(Dictionary<string, object> result)
        {
            CultureInfo provider = CultureInfo.InvariantCulture;

            // Extract the info out of the host dictionary and put it in the local properties
            Id = int.Parse(result["id"].ToString());
            Author = result["author"] as string;
            Date = DateTime.ParseExact((string)result["date"], "dd.MM.yyyy", provider);
            Description = result["description"] as string;
            Platform = result["platform"] as string;
            Port = int.Parse(result["port"].ToString());
            Type = result["type"] as string;
            CVE = result["type"] as string;
        }

        public int Id { get; set; }
        public string Author { get; set; }
        public DateTime Date { get; set; }
        public string Description { get; set; }
        public string Platform { get; set; }
        public int Port { get; set; }
        public string Type { get; set; }
        public string CVE { get; set; }
    }

    public class ServiceBanner
    {
        public ServiceBanner(int argPort, string argBanner, DateTime argTimestamp)
        {
            Port = argPort;
            Banner = argBanner;
            Timestamp = argTimestamp;
        }

        public int Port { get; private set; }
        public string Banner { get; private set; }
        public DateTime Timestamp { get; private set; }
    }

    public class HostLocation
    {
        public HostLocation(Dictionary<string, object> host)
        {
            // Extract the info out of the host dictionary and put it in the local properties
            if (host.ContainsKey("country_name"))
                CountryName = (string)host["country_name"];

            if (host.ContainsKey("country_code"))
                CountryCode = (string)host["country_code"];

            if (host.ContainsKey("city"))
                City = (string)host["city"];

            if (host.ContainsKey("latitude"))
            {
                Latitude = (double)((decimal)host["latitude"]);
                Longitude = (double)((decimal)host["longitude"]);
            }
        }

        public string CountryCode { get; private set; }
        public string CountryName { get; private set; }
        public string City { get; private set; }
        public double Latitude { get; private set; }
        public double Longitude { get; private set; }

        /// <summary>
        ///   Check whether there are valid coordinates available for this location.
        /// </summary>
        /// <returns> true if there are latitude/ longitude coordinates, false otherwise. </returns>
        public bool HasCoordinates()
        {
            if (Latitude != 0 && Longitude != 0)
                return true;

            return false;
        }
    }

    public class Host
    {
        public Host(Dictionary<string, object> host, bool simple = false)
        {
            CultureInfo provider = CultureInfo.InvariantCulture;

            // Extract the info out of the host dictionary and put it in the local properties
            IP = IPAddress.Parse(host["ip"].ToString());

            // Hostnames
            ArrayList tmp = (ArrayList)host["hostnames"];
            Hostnames = tmp.Cast<string>().ToList();

            // Banners
            Banners = new List<ServiceBanner>();

            if (host["data"] is ArrayList)
            {
                tmp = (ArrayList)host["data"];
                foreach (Dictionary<string, object> data in tmp)
                {
                    DateTime timestamp = DateTime.ParseExact((string)data["timestamp"], "dd.MM.yyyy", provider);
                    Banners.Add(new ServiceBanner((int)data["port"], (string)data["banner"], timestamp));
                }
            }
            else if (host["data"] is string)
            {
                DateTime timestamp = DateTime.ParseExact((string)host["updated"], "dd.MM.yyyy", provider);
                Banners.Add(new ServiceBanner((int)host["port"], (string)host["data"], timestamp));
            }

            // Location
            Location = new HostLocation(host);

            IsSimple = simple;
        }

        public List<ServiceBanner> Banners { get; private set; }
        public IPAddress IP { get; private set; }
        public List<string> Hostnames { get; private set; }
        public HostLocation Location { get; private set; }

        /// <summary>
        /// Used to differentiate between hosts from Search() results and direct GetHost() queries
        /// </summary>
        public bool IsSimple { get; private set; }
    }

    public class DataResponse
    {
        public DataResponse(Dictionary<string, object> data)
        {
            Data = data["data"] as string;
            ContentType = data["content-type"] as string;
            Filename = data["filename"] as string;
        }

        public string Data { get; set; }
        public string ContentType { get; set; }
        public string Filename { get; set; }

        public void WriteToFile(string path)
        {
            if (!Directory.Exists(path))
                Directory.CreateDirectory(Path.GetDirectoryName(path));

            File.WriteAllText(path, Data);
        }
    }

    public class MSFModule
    {
        public MSFModule(Dictionary<string, object> data)
        {
            Alias = data["alias"] as string;
            Arch = data["arch"] as string;

            ArrayList authors = data["authors"] as ArrayList;
            if (authors != null)
                Authors = new List<string>(authors.Cast<string>());

            Description = data["description"].ToString();
            Fullname = data["fullname"].ToString();
            Name = data["name"].ToString();

            ArrayList platforms = data["platforms"] as ArrayList;
            if (platforms != null)
                Platforms = new List<string>(platforms.Cast<string>());

            Privileged = bool.Parse(data["privileged"].ToString());
            Rank = data["rank"] as string;

            ArrayList references = data["references"] as ArrayList;
            if (references != null)
            {
                References = new List<KeyValuePair<string, string>>();
                foreach (ArrayList reference in references)
                {
                    References.Add(new KeyValuePair<string, string>(reference[0].ToString(), reference[1].ToString()));
                }
            }

            Type = data["type"] as string;
            Version = data["version"] as string;
        }

        public string Alias { get; set; }
        public string Arch { get; set; }
        public List<string> Authors { get; set; }
        public string Description { get; set; }
        public string Fullname { get; set; }
        public string Name { get; set; }
        public List<string> Platforms { get; set; }
        public bool Privileged { get; set; }
        public string Rank { get; set; }
        public List<KeyValuePair<string, string>> References { get; set; }
        public string Type { get; set; }
        public string Version { get; set; }
    }
}