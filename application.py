from shim_layer import *


#TODO: Create models based on Phold

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination> <process_id>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    pid = int(sys.argv[2])

    shim = shim_layer(pid)

    while True:
        x = input()
        shim.send(addr, input=x)


if __name__ == '__main__':
    main()
