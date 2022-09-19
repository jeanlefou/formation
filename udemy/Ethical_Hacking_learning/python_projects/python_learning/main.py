import utility
import gardening.water_utility as test
# from package.module import function

# no need to close file mode=r/r+ (rw)
# r+ : read-write
# w = overwrite/create file
# a : appaend
with open('test.txt', mode='a') as file:
    #print(file.readlines())
    file.write('toutou')
    

#file = open('.gitignore')
#print(file.read())
#print(file.read())
#file.seek(0)
#print(file.read())
#print(file.readline())
#file.seek(42)
#print(file.readline())
#print(file.readlines())
#
## WARNING : it's important to close file to free memory
#file.close()

#print("You are " + str(utility.get_age()) + " years old.")
#utility.test_err()

# print path to package
#print(utility)
#
#print(utility.double_sum(4,2))
#print(utility.triple_sum(4,2,num1=6,num2=9))
#
#watered_plants = []
#print(test.water(watered_plants,'rose'))
#print(test.water(watered_plants,'tulip'))


#def hello(name="default name"):
#    '''
#    doctring : a function description
#    '''
#    print(f'hi {name}')
#
#hello()
#help(hello)
#print(hello.__doc__)
#picture = [
#    [0,0,0,1,0,0,0],
#    [0,0,1,1,1,0,0],
#    [0,1,1,1,1,1,0],
#    [1,1,1,1,1,1,1],
#    [0,0,0,1,0,0,0],
#    [0,0,0,1,0,0,0],
#]
#
#for l in picture:
#    for p in l:
#        if p == 0:
#            print(' ',end='')
#        elif p == 1:
#            print('*',end='')
#        else:
#            print(' ',end='None')
#    print()

#for i,char in enumerate('hellooosidskdjs'):
#    print(i,char)

#is_friend = True
#can_message = "message allowed" if is_friend else "not allowed"
#print(can_message)

#a_set = {1,2,3,4,5,5,5}
#b_set = {5,5,6,7,8,9}
#a_set.add(100)
#a_set.add(2)
#print(a_set)
#print(2 in a_set)
#print(list(a_set)) #converts to a new list
#print(a_set | b_set)
#tup = (1,2,3,4,5,6)

#dic = {
#    'a': 1,
#    'b': 2,
#    'f': [1,2,5],
#    'x': 2,
#    'c': 3
#}
#test=dict(name='tintin') #creat dic
#print(test)
#print('x' in dic)
#print('dada' in dic.keys())
#print(dic.items())
#dic.clear()
#print(dic['f'][2])
#print(dic)

#matrix = [
#    [1,2,3],
#    [4,5,6],
#    [7,8,9],
#    [10,11,12],
#]
#print(matrix[1][2])

#li = [1,2,3,4,5,6]
#li2 = ['a','b','c']
#li3 = [1,2,'a',True,8,9,6,5]
#print(li)
#print(li2[2])
#print(li3[0:8:2])
#li3[2] = 'patate'
#print(li3[0:8:2])
#li4 = li3
#li5 = li3[:]
#print(li4)
#print(li5)


#test = input('Enter a value\n')
#print("entered value = " + test)
#vara='azerty'
#varb=len(vara)
#varc=vara
#print(varb)
#print(varc)