import json

# 初始化devices字典
devices = {}

def get_level(i):
    if i == 1:
        return "level1"
    elif i in [2, 3]:
        return "level2"
    elif 4 <= i <= 7:
        return "level3"
    elif 8 <= i <= 15:
        return "level4"
    elif 16 <= i <= 31:
        return "level5"
    elif 32 <= i <= 63:
        return "level6"
    else:
        return "level7"

# 循环创建100个设备
for i in range(1, 101):
    device_id = f"device:domain1:group4:{get_level(i)}:s{300+i}"  # 格式化设备ID，确保它是5位数
    devices[device_id] = {
        "basic": {
            "managementAddress": f"grpc://218.199.84.171:{50001 + i - 1}?device_id=1",
            "driver": "stratum-bmv2",
            "pipeconf": "org.stratumproject.basic.bmv2"
        }
    }

# 创建最终的JSON对象
json_data = {"devices": devices}

# 将JSON对象转换为字符串，格式化输出
json_str = json.dumps(json_data, indent=2)

# 打印JSON字符串
print(json_str)

# 可以选择将JSON字符串写入文件
with open('tofino-netcfg.json', 'w') as f:
    f.write(json_str)