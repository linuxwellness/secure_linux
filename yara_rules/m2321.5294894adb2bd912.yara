
rule m2321_5294894adb2bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5294894adb2bd912"
     cluster="m2321.5294894adb2bd912"
     cluster_size="28"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shiz backdoor zusy"
     md5_hashes="['18a5ac119484438b68c6129b711100e5','1b84d7a9e5bd1781e84e9d7792ea1414','a841fb5bf66be3724f6125e6c9fafe11']"

   strings:
      $hex_string = { 852de8be286ca4edd5cccfab490972b4a15c21c3f0d1315497f3a8f735b9448c016dfb3764e9ad2e0d3b1762f61ddfd6f5a67434aa8c8afc590c82ac864b4c71 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
