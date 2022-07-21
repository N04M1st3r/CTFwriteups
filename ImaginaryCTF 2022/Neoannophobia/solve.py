from pwn import *

host, port = "neoannophobia.chal.imaginaryctf.org", 1337

#diconary of all the months and their 
months = {
	'January': 1,
	'February': 2,
	'March': 3,
	'April': 4,
	'May': 5,
	'June': 6,
	'July': 7,
	'August': 8,
	'September': 9,
	'October': 10,
	'November': 11,
	'December': 12
}

#returns the month as a number (1-12) (in the Gregorian calendar).
def month_to_int(month_str):
	return months[month_str]

#opposite of getMonthAsNumber, gets a number from 1-12 and returns what month it is (in the Gregorian calendar).
def int_to_month(month_num):
	return list(months.keys())[month_num-1]

	#this code will be slow (O(n)) but its only 12 months so its fine
	#can make it faster by just declering a list before that will hold months.keys() in a list way
	#so this code won't do it everytime, that would make this code O(1)


#examples of what to do to get to the win:

#win winD:   December 31

#win seq1:  November 30 --> winD

#win seq2:  October 29 --> winD
#		    October 29 --> seq1

#win seq3:  September 28 --> winD
#           September 28 --> seq2
#			September 28 --> seq3

#win seq4:  August 27 --> winD
#			August 27 --> seq2
#			August 27 --> seq3
#			August 27 --> seq4

#seq 5: July 26 ...

#seq 6: June 25 ...

#seq 7: May 24 ...

#seq 8: April 23 ...

#seq 9: March 22 ...

#seq 10: February 21 ...

#seq 11: January 20 ...
 #can win here by:

#longest Path: January 20 --> February 21 -> March 22 -> ... -> November 30 -> winD 

#returns the month and day I need to input to win!
#calculates the best move to do
def best_move(month_str, day):
	if (month_str=='December' or day==31):
		res_day = 31
		res_month = 'December'
		return (res_month, res_day)

	month_num = month_to_int(month_str)

	if(day - month_num + 1 == 20):
		#if here, you lost if he won't make a mistake..
		#the best way to avoid the loss is to try slow him down(won't work 100%):
		res_month = int_to_month(month_num)
		res_day = day+1 #if it reaches 31 you lose anyway
	else:
		#You got the win!
		#just follow what I tell u to do!
		if(day - month_num + 1 > 20):
			#solved the following equation for month_num: day - month_num + 1 = 20
			res_month = int_to_month(day + 1 - 20)

			res_day = day
		else: #(day - month_num + 1 < 20)
			res_month = int_to_month(month_num)

			#solved the following equation for day: day - month_num + 1 = 20
			res_day = 20 + month_num - 1

	return res_month, res_day
		
def parseInput(text):
	computer_input = text.split('\n')[-2].split(' ')
	month = computer_input[0]
	day = int(computer_input[1])

	return month, day



p = connect(host, port)

wins = 0
text1 = p.recvuntil(b'> ').decode()
while wins!=100:

	computer_month, comouter_day = parseInput(text1)
	#print("Computer: ", computer_month, comouter_day)
	
	month, day = best_move(computer_month, comouter_day)
	sendBytes = f"{month} {day}".encode()
	#print("User: ", month, day)

	p.sendline(sendBytes)

	text1 = p.recv().decode()
	if "You won!" in text1:
		wins+=1
		print(f"win number: {wins}")


print(text1)
flag = text1.split('\n')[1]

print(f"{flag=}")

p.close()
