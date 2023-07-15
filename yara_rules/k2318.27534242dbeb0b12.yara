
rule k2318_27534242dbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27534242dbeb0b12"
     cluster="k2318.27534242dbeb0b12"
     cluster_size="79"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['30ab1bf5aee7780a5654e58e40d95a79365dc2a9','06f1ddc1d227863554cc1a44d14af2e1e99899b4','8574f58c5cd126f2142e616f7e01e2cbdcb412e2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27534242dbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
