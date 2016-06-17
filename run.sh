./producer -e -paditya foo 2.txt &
./producer -c -n high foo 91.txt &
./producer -e -n high -paditya foo 2.txt &
./producer -s foo &
./producer -c foo 9.txt &
./producer -s foo &
./producer -e -paditya foo 661.txt &
./producer -c -n high foo 91.txt &
./producer -e -n high -paditya foo 2.txt &
./producer -e -n high -paditya foo 2.txt &
./producer -d -w -paditya 2.txt 23.txt &
./producer -d -w -paditya 2.txt 23.txt &
./producer -d -w -paditya 2.txt 23.txt &
./producer -l
