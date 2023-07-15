
rule k2321_0b929cc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0b929cc9cc000912"
     cluster="k2321.0b929cc9cc000912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['3c188e9d81b73d3cfde2706c9df9f9e9','53ab5ee89cf1f9a3e8c754961740d869','f27d725bc9cc9f98a830e0062762b53c']"

   strings:
      $hex_string = { 6b1f9542b5d9e2de60b6eed1d31ad19bb97b0c2c93cd84516d36a13422b11c859140e4efa2532473dc9faa41b6c82014cb7c04da0303797a67ae38d6560ab24f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
