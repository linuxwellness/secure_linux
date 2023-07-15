
rule k2321_2a40a856166b48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a40a856166b48ba"
     cluster="k2321.2a40a856166b48ba"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['526f61cbee1458b32476782961dbcb82','54c035b4a6efdf1381adb75065b47787','a17d7d153481137a355ebad70299e265']"

   strings:
      $hex_string = { 147ff0466fbfab35c09cd89fc705246800126466a40de5626e89b4a35c21d6b079fad1d3efd2c5778c5fa245c38d734094827a42d543597c753c3bc6600b7074 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
