
rule i3ec_06b5994cd3eb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ec.06b5994cd3eb0b32"
     cluster="i3ec.06b5994cd3eb0b32"
     cluster_size="8"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['31ee89d354c317413b2b25c3464364e6','3c0c6e132fa0e760cdbb2cdf41cc31d0','f7b3f1f318b17bd2ca3d5949e88cfb30']"

   strings:
      $hex_string = { f75766cfdaa1ebb34f457c2b6c8f8bd986986d7576f5a9b475c7ecb763031faa9ecbefc6a6fceebeb9a3f6e6c08a4ab6ee81285895374d671eddf9c5875f6ec9 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
