namespace JaggerJoFauxlemetry

open System
open System.Text.Json
open System.Text.Json.Serialization
open Redis.OM
open Redis.OM.Modeling

[<AutoOpen>]
module EventGenerator =

    type EventRecord =
        { epoch_timestamp: int64
          EventTime: string
          cst_id: string
          src_ip: string
          src_port: string
          dst_ip: string
          dst_port: string
          cc: string
          vpn: string
          proxy: string
          tor: string
          malware: string }

    [<Document(StorageType = StorageType.Json, Stopwords = [| |], Prefixes = [|"Customer:"|])>]
    type RawDataModel() =

        [<RedisIdField>] [<Indexed>]
        member val Id = "" with get, set

        [<Indexed(Aggregatable = true)>]
        member val epoch_timestamp : int64 = 0 with get, set

        [<Indexed>]
        member val EventTime = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val cst_id  = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val src_ip = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val src_port = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val dst_ip = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val dst_port = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val cc = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val vpn = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val proxy = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val tor = "" with get, set

        [<Searchable(Aggregatable = true)>]
        member val malware = false with get, set

    [<JsonFSharpConverter>]
    type Example = EventRecord

    let environment = "redis://localhost:6379"
    let provider = RedisConnectionProvider(environment)
    let connection = provider.Connection

    let mutable currentTime = DateTime.Now.ToString("hh:mm:ss.fff")
    let customer = "DAD86E169793491181B523C8D458AE32"
    let rewind = 15

    let volume = 1
    let rec createMomentForCompany =
        async {
            // set up random functions
            let rnd = Random()

            // build an array of randomized time values millis (0 padded)
            let randomMillis =
                [| for i in 0 .. (volume-1)->
                         rnd.Next(1000).ToString().PadLeft(3, '0')
                |]

            // build an array of fake timestamps from the above arrays and sort chronologically (as array of string)
            let randomTimeStamps =
                let DateTimeSecond = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss")
                [| for i in 0 .. (volume-1)->
                         DateTimeSecond
                         + "."
                         + randomMillis[i]
                |]

            // Prevents the creating of an unnecessary array
            randomTimeStamps
            |> Array.sortInPlace

            let epoch_timestamps : int64 array =
                [| for i in 0 .. (volume-1) ->
                    DateTimeOffset(DateTime.Parse(randomTimeStamps[i]).ToUniversalTime()).ToUnixTimeMilliseconds()
                |]

            // TODO: This should be a lookup of some sort - by country
            let srcIpFirstOctets = "160.72"

            let destIpFirstOctets = "11.18"

            // build an array of randomized octets (3, 4) for the Source and Destination IPv4
            let randomSrcOctets3 =
                [| for i in 0 .. (volume-1)->
                         rnd.Next(256).ToString().PadLeft(3, '0')
                |]

            let randomSrcOctets4 =
                [| for i in 0 .. (volume-1)->
                         rnd.Next(256).ToString().PadLeft(3, '0')
                |]

            let randomDestOctets3 =
                [| for i in 0 .. (volume-1)->
                         rnd.Next(256).ToString().PadLeft(3, '0')
                |]

            let randomDestOctets4 =
                [| for i in 0 .. (volume-1)->
                         rnd.Next(256).ToString().PadLeft(3, '0')
                |]

            // build an array of fake IPv4s from constants and arrays above
            let randomSrcIPv4 =
                [| for i in 0 .. (volume-1)->
                         srcIpFirstOctets
                         + "."
                         + randomSrcOctets3[i]
                         + "."
                         + randomSrcOctets4[i]
                |]

            let randomDestIPv4 =
                [| for i in 0 .. (volume-1)->
                         destIpFirstOctets
                         + "."
                         + randomDestOctets3[i]
                         + "."
                         + randomDestOctets4[i]
                |]

            let randomSrcPort =
                [| for i in 0 .. (volume-1)->
                         let randomSrcPort = rnd.Next (1, 101)
                         match randomSrcPort with
                         | i when i > 90 -> rnd.Next(1025, 65535).ToString()
                         | _ -> "80"
                |]

            let randomDestPort =
                [| for i in 0 .. (volume-1)->
                         let randomDestPort = rnd.Next (1, 101)
                         match randomDestPort with
                         | i when i > 90 -> rnd.Next(1025, 65535).ToString()
                         | _ -> "80"
                |]

            // generate array of countries - bias is built from Cloudflare DDoS source country top 10
            let randomCC =
                [| for i in 0 .. (volume-1)->
                         let randomCountry = rnd.Next (1, 101)
                         match randomCountry with
                         | _ -> "RU"
                |]

            // Generate VPN entries for 30% of elements using shuffleR function (and taking top [head] value)
            let VpnClients =
                [| for i in 0 .. (volume-1)->
                         let randomVPN = rnd.Next (1, 101)
                         match randomVPN with
                         | i when i > 1 && i <= 5 -> "nord;proton"
                         | i when i > 5 && i <= 10 -> "nord;surfshark"
                         | i when i > 10 && i <= 15 -> "nord;foxyproxy"
                         | i when i > 15 && i <= 18 -> "purevpn"
                         | i when i > 18 && i <= 21 -> "proton"
                         | i when i > 21 && i <= 24 -> "nord"
                         | i when i > 24 && i <= 27 -> "foxyproxy"
                         | i when i > 27 && i <= 30 -> "surfshark"
                         | _ -> "BLANK"
                |]

            // generate proxy values - use VpnClients value if present, otherwise create a new value
            let ProxyClients =
                [| for i in 0 .. (volume-1)->
                         let randomProxy = rnd.Next (1, 101)
                         if randomProxy <= 30 then
                             if VpnClients[i] <> "" && VpnClients[i] <> "BLANK" then
                                 VpnClients[i]
                             else
                                 match randomProxy with
                                 | i when i > 1 && i <= 5 -> "nord;proton"
                                 | i when i > 5 && i <= 10 -> "nord;surfshark"
                                 | i when i > 10 && i <= 15 -> "nord;foxyproxy"
                                 | i when i > 15 && i <= 18 -> "purevpn"
                                 | i when i > 18 && i <= 21 -> "proton"
                                 | i when i > 21 && i <= 24 -> "nord"
                                 | i when i > 24 && i <= 27 -> "foxyproxy"
                                 | i when i > 27 && i <= 30 -> "surfshark"
                                 | _ -> "BLANK"
                         else
                             "BLANK"
                |]

            // Tor values [30%] use VpnClients or ProxyClients value if present, otherwise create new
            let TorClients =
                [| for i in 0 .. (volume-1)->
                         let randomTor = rnd.Next (1, 101)
                         if randomTor <=30 then
                             if VpnClients[i] <> "BLANK" ||  ProxyClients[i] <> "BLANK" then
                                 if VpnClients[i] <> "BLANK" then
                                    VpnClients[i]
                                 else
                                    ProxyClients[i]
                             else
                                 match randomTor with
                                 | i when i > 1 && i <= 5 -> "nord;proton"
                                 | i when i > 5 && i <= 10 -> "nord;surfshark"
                                 | i when i > 10 && i <= 15 -> "nord;foxyproxy"
                                 | i when i > 15 && i <= 18 -> "purevpn"
                                 | i when i > 18 && i <= 21 -> "proton"
                                 | i when i > 21 && i <= 24 -> "nord"
                                 | i when i > 24 && i <= 27 -> "foxyproxy"
                                 | i when i > 27 && i <= 30 -> "surfshark"
                                 | _ -> "BLANK"
                         else
                             "BLANK"
                |]

            // set up an array for MAL booleans - 20% TRUE
            let MalBoolean =
                [| for i in 0 .. (volume-1)->
                         let randomMAL = rnd.Next (1, 101)
                         match randomMAL with
                         | i when i = 100 -> "UNKNOWN"
                         | i when i >= 79 && i <= 99 -> "TRUE"
                         | _ -> "FALSE"
                |]

            // create full JSON serializable array
            let DayRecords =
                [| for i in 0 .. (volume-1)->
                     { epoch_timestamp = epoch_timestamps[i];
                         EventTime = randomTimeStamps[i];
                         cst_id = customer;
                         src_ip = randomSrcIPv4[i];
                         src_port = randomSrcPort[i];
                         dst_ip = randomDestIPv4[i];
                         dst_port = randomDestPort[i];
                         cc = randomCC[i];
                         vpn = VpnClients[i];
                         proxy = ProxyClients[i];
                         tor = TorClients[i];
                         malware = MalBoolean[i]
                         }
                |]

            let TTLValue = rewind
            let serializeRecord (event: EventRecord) =
                let newKey = "Customer:"+customer+":"+Guid.NewGuid().ToString("N")
                Console.WriteLine("writing record " + newKey + "")
                connection.Execute("JSON.SET", newKey, "$", JsonSerializer.Serialize(event)) |> ignore
                let dateTimeNowSeconds = DateTimeOffset(DateTime.Now).ToUnixTimeSeconds()
                let eventExpirationInSeconds = DateTimeOffset(DateTime.Parse(event.EventTime).AddDays(TTLValue)).ToUnixTimeSeconds()
                let eventTtl = eventExpirationInSeconds - dateTimeNowSeconds
                connection.Execute("EXPIRE", newKey, eventTtl.ToString())

            // serialize JSON
            let options = JsonSerializerOptions()
            options.Converters.Add(JsonFSharpConverter())

            DayRecords
                |> Array.map serializeRecord
                |> ignore

        }
