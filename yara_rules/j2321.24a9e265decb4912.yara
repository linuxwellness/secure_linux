
rule j2321_24a9e265decb4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.24a9e265decb4912"
     cluster="j2321.24a9e265decb4912"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="selfdel generickd upatre"
     md5_hashes="['186b80caca043b55c25a4997d94e7351','769acd9aa6fc15a9ac41db716fe298b5','e28c5ee34005f7951f257539dab4858f']"

   strings:
      $hex_string = { 7e0dbf1e128274973ba65114df636e8d423f0ece4f9a85f5a063a52fa03d7b0b8ed5207fbb6e537250cff3fa4027945ff82b6c46f99103fb6f47b9ef35d1d461 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
