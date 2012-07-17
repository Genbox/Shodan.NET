# Shodan.NET - A full implementation of the ShodanHQ.com API

The Shodan.NET class library build in .net 4.0 C#, provides a class to search, getting host information, exploits from ExploitDB and more.

### Features

* Search hosts based on a string
* Get detailed information, including service banners from a single IP
* Search and download exploits from ExploitDB and modules from the MSF (Metasploit Framework)

### Usage

Before you can use the API, you need to have an API key.

[Get your API key here](http://www.shodanhq.com/api_doc)

###Examples
Print a list of cisco-ios devices:
```csharp
Shodan shodan = new Shodan("YOUR API KEY");
List<Host> hosts = shodan.Search("cisco-ios");

foreach (Host h in hosts)
{
	Console.WriteLine(h.IP.ToString());
}
```

Get all the information SHODAN has on the IP 217.140.75.46:
```csharp
Host host = shodan.GetHost("217.140.75.46");
Console.WriteLine(host.IP.ToString());
```

Search for exploits on ExploitDB and modules on MSF:
```csharp
List<Exploit> exploits = shodan.SearchExploits("Microsoft Windows XP");

foreach (Exploit exploit in exploits)
{
	Console.WriteLine(exploit.Description);
}

List<MSFModule> modules = shodan.SearchMSFModules("Oracle");

foreach (MSFModule msfModule in modules)
{
	Console.WriteLine(msfModule.Name);
}
```

Download exploit from ExploitDB and modules from MSF:
```csharp
DataResponse exploitData = shodan.DownloadExploit(17133);
Console.WriteLine(exploitData.Filename);

//Note that we also write the file to disk
DataResponse module = shodan.DownloadMSFModule("exploit/windows/browser/ms06_055_vml_method");
module.WriteToFile("C:\\" + module.Filename);
Console.WriteLine(module.Filename);
```

See the Shodan.NET Client inside the project to try out the API.