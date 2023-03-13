#!/bin/bash

while true; do 
    echo "=> Select all schema names from information_schema.schemata"
  
    psql -h proxy -p 8989 -U postgres -c "select * from information_schema.schemata;"

    sleep 10s
done

#psql -h proxy -p 5432 -U postgres -c "select * from information_schema.schemata;"
#psql -h postgres -p 5432 -U postgres -c "select * from information_schema.schemata;"