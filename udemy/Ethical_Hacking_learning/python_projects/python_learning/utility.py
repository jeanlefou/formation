

def double_sum(*args):
    return sum(args)*2

def triple_sum(*args, **kwargs):
    total = 0
    print(kwargs)
    for items in kwargs.values():
        total += items
    return total*3

def get_age():
    try:
        return int(input('How old are you?'))
    except:
        print('please enter a number')
        return get_age()

def test_err():
    while True:
        try:
            nb = int(input('Enter a nb :'))
            10/nb
            raise Exception('Test exception') # don't use except block and stop exec
        except (ValueError,TypeError) as err:
            print('please enter a number')
            print(err)
            continue #comes back to top of while loop without going to else block
        except ZeroDivisionError as err:
            print('please enter a nb > 0, error :')
            print(err)
            break
        else:
            print('thanks.')
            break
        finally: #always run at the end of try except block regardly, even after the else block
            # usefull to log msg at each loop, example : log and detect brute force
            print('finally block')
