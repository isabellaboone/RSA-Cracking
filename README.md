# RSA Project CMPE320 
An attempt at cracking high bit RSA keys using Pollard Rho's prime factorization. 

# Our Record
120 bit key in 64675356usecs

# Running
- The program automatically runs all keys from 12-200 bits and logs output to `times.txt`

1. `make`
2. `./find-key` :) 
3. check `times.txt` for how fast each key was cracked and what the message was. 
4. program will run infinitely, so you should either terminate after cracking 120 key, or modify the for loop in find-key.c's main method. 

# Notes
- Although the program is set to run to up 200 bit keys, we haven't been able to crack further than 120 bit keys, even with the program running overnight.
- We might be able to push our record with the brent modification :) 

# Authors
- Isabella Boone 
- John Gable
- Joshua Lewis

