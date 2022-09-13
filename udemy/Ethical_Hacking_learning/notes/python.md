# Section 21 : python bases
## datatype
- native : int, float, bool, str, list, tuple, set, dict, complex
- classes = custom types
- spezialized data types (module.*)
- None (=NULL)


# operators
`a ** b` = a^b
`a // b` = a/b round to lower integer
`a % b` = modulo (reste division euclienne -> a//b)

# math functions
https://docs.python.org/3
round(), abs(), https://docs.python.org/3/library/math.html#module-math
bin()

# variables

# expressions VS statement
- expression : "50/5", piece of code that produce value/results
- statement : line of code doing an action (var assign, etc.)

# Augmented assignment operator (+=, -=, etc)

# type conversion
str(), int()

# formatted string
```
vara='ddd'
varb='fff'
print(f'{vara} {varb}')
```

# string index
```
vara='ttrtaratat'
print(vara[2])
print(vara[2:5])
print(vara[start:stop:stepover])
print(vara[::-1]) #reverse string
```
**WARNING : string index starts at 1, not 0**

# Immutability
string in python are immutable (possible to reassign, but not modify)

## [builtin functions](https://docs.python.org/3/library/functions.html)
```
vara='azerty'
varb=vara.len()
```

possible to embed function in print fcuntion with f option :
```
print(f'{vara} {len(varb)}')
```

## data structures
### list
- ordered with index
- data structure = container around data with metho to access it
- = array in other languages
- **index starts at 0**
- list are mutable ( != vars)
- [methods](https://www.w3schools.com/python/python_ref_list.asp)
sort(li1) = sort li1
sorted(li1) = create a sorted copy of li1 (= new list)
range(101) # creates a list from 0 to 101

```
li = [1,2,3,4,5,6]
li2 = ['a','b','c']
li3 = [1,2,'a',True,8,9,6,5]
print(len(li))
print(li2[2])
print(li3[0:8:2])
li3[2] = 'patate'
print(li3[0:8:2]) #list slicing creates a new list, no modif on original list
li4 = li3
li5 = li3[:]
print(li4)
print(li5)
print('9' in li3)
sentence=' '
new_sent = sentence.joint(['word1','word2','word3'])
new_sent_bis = ' '.joint(['word1','word2','word3'])
```
list unpacking :
```
a,b,c = 1,2,3
print(a)
print(c)
a,b,c,*other,d = [1,2,3,4,5,6,7,8,9]
print(other)
print(d)
```


### matrix
```
matrix = [
    [1,2,3],
    [4,5,6],
    [7,8,9],
    [10,11,12],
]
print(matrix[1][2])
```


### Dictonary
- not ordered but k-v
- dic key must be immutable and unique
- dic are mutable
```
dic = {
    'a': 1,
    'b': 2,
    'f': [1,2,5],
    'x': 2,
    'c': 3
}
test=dict(name='tintin') #creat dic
print(test)
print('x' in dic)
print(dic.get('f',"ret if f not exists")) # return None instead or err when key does'nt exists
print('dada' in dic.keys()) # dic.values()
print(dic.items())
dic.clear()
print(dic['f'][2])
print(dic)
```
[methods](https://www.w3schools.com/python/python_dictionaries_methods.asp)

### tuples
- immutable list
`dic.items() #return dic objects as tuple`
- slicing : like string and lists

### Sets
- all value unique in set
- [methods](https://www.w3schools.com/python/python_sets_methods.asp)
```
a_set = {1,2,3,4,5,5,5}
b_set = {5,5,6,7,8,9}
a_set.add(100)
a_set.add(2)
print(a_set)
print(2 in a_set)
print(list(a_set)) #converts to a new list
print(a_set | b_set)
```

## [Truthly & Falsy](https://stackoverflow.com/questions/39983695/what-is-truthy-and-falsy-how-is-it-different-from-true-and-false)
Falsy : None, 0, 0.0, Decimal(0), etc.
Truly : 1, True, etc.

## Ternary operators
cond_if_t if condition else condition_if_else
```
is_friend = True
can_message = "message allowed" if is_friend else "not allowed"
print(can_message)
```
## operators & loops
and, or, else, ==, <, >, is (check if location in memory is =)
**'==' != 'is'**
```
if condition:
    ...
elif condition2:
    ...

elif not condition:
    ...
```

### iterable
- list, dic, set, tuples, string
```
for _ in range(5,103,7):
    print(_)
for _ in range(103,9,-7):
    print(_)
for i,char in enumerate('hellooosidskdjs'):
    print(i,char)
```

break : break out of loop
continue : continue to next loop pass
pass : do nothing, (go to next line), don't creates an error if no code in loop

## functions
- arguments : passed to function calls
- parameters : in function def

```
def hello(name="default name"):
    '''
    doctring : a function description
    '''
    print(f'hi {name}')
# print function docstring
help(hello)
print(hello.__doc__)
hello()
```

function(arg)
object.method()

### *args & **kwards
- rule : params, *args, default params, **kwargs
```
def double_sum(*args):
    return sum(args)*2
print(double_sum(4,2))

def triple_sum(*args, **kwargs):
    total = 0
    print(kwargs)
    for items in kwargs.values():
        total += items
    return total*3
print(triple_sum(4,2,num1=6,num2=9))
```

## Scope in python
- similar than other languages
- access non local vars : `nonlocal x` -> not good for readability
- after function is finished, gargage collector auto-rm local objects

## Modules in python
- [classes + scope doc](https://docs.python.org/3/tutorial/classes.html)
- ref to vanille "python_learning" py project folder

## Error handling
- [builtin exception](https://docs.python.org/3/library/exceptions.html)
- ref to vanille "python_learning" py project folder

## Python File I/O
- ref to vanille "python_learning" py project folder

## [Purepath lib (win and*nix compatible paths)](https://docs.python.org/fr/3/library/pathlib.html)


```
```
```
```