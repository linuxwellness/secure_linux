
rule k3e9_51b933065da31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b933065da31932"
     cluster="k3e9.51b933065da31932"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['354a769c59bbb19df61202a9e7193dd5','bf7f710d5a60b5839ffbba75ff1a9316','de6d7d8bf8cceec24edf828c483aaa63']"

   strings:
      $hex_string = { 0003000150000000002800530056000a00e803ffff8000260044006f006e00270074002000720065006d0069006e00640020006d006500200061006700610069 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
