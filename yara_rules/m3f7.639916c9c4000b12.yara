
rule m3f7_639916c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.639916c9c4000b12"
     cluster="m3f7.639916c9c4000b12"
     cluster_size="19"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['00ac07d41d058672eb675f73514a502f','1acf07b8a67359084c80e6db8240c065','e4f39d6fda64d2d5e683a7e11aad2bdd']"

   strings:
      $hex_string = { 63726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
