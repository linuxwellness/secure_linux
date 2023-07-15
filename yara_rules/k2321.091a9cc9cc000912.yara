
rule k2321_091a9cc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.091a9cc9cc000912"
     cluster="k2321.091a9cc9cc000912"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos qqhelper"
     md5_hashes="['075b665c1d62c926edd18c847506809c','3bb35a9bb8771e6a46b5dff440190092','fdd110a8aa6dd93fdacf93e64faea13a']"

   strings:
      $hex_string = { 594c20d7af5235f84f99e8a1aab0ef2a54615740156845265405b9caefa50e2ef310a328845f1b22e9620991174b70ed30a0186eb6cfddd8dfc31e9d41abfbc0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
