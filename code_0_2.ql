import cpp

from Macro m
where m.getName() = "ntohl" or m.getName() = "ntohll" or m.getName() = "ntohs"
select m
