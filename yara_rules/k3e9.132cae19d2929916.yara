
rule k3e9_132cae19d2929916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.132cae19d2929916"
     cluster="k3e9.132cae19d2929916"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart berbew backdoor"
     md5_hashes="['11db79a495fd5399d51e61a115ec4a40','34e3184506da963572682a2d937da7b6','9e9a203b5a23475f8756470439a2256e']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
