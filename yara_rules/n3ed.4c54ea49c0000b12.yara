
rule n3ed_4c54ea49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4c54ea49c0000b12"
     cluster="n3ed.4c54ea49c0000b12"
     cluster_size="113"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['0029d30172e5e0e15c8971af5b70dd04','016bdab8559b57567a23d41d17c2bde3','4e5767174bb472306eae389a1c2b4c8c']"

   strings:
      $hex_string = { 403bc672be8b4dfc5ee8b3a3ffffc9c3558bec83ec1ca1f481011053568b750833db3bf38945fc570f845401000033d233c039b0688a0110746583c030423df0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
