import re
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
from functools import lru_cache
import json


# ==================== 文件名解析模块 ====================
def parse_filename(filename):
    """
    统一解析文件名格式：标识符_内容_金额XX元_XX张.txt
    返回结构：{
        "identifier": str,
        "content": str,
        "amount": str,
        "quantity": str
    }
    """
    pattern = r"^(.+?)_(.+?)_金额(\d+)元_(\d+)张\.txt$"
    match = re.match(pattern, filename)
    if not match:
        raise ValueError("文件名格式错误，请使用：标识符_内容_金额XX元_XX张.txt")

    return {
        "identifier": match.group(1),
        "content": match.group(2),
        "amount": match.group(3),
        "quantity": match.group(4)
    }


# ==================== 图片生成核心模块 ====================
@lru_cache(maxsize=32)
def generate_ticket_image(filename_data_str, line_data_str, index, total):
    try:
        filename_data = json.loads(filename_data_str)
        line = line_data_str.strip()

        # 样式配置
        IMG_SIZE = (700, 900)
        MARGIN = 40
        FONT_CONFIG = {
            'header': 34,
            'content': 30,
            'amount': 40,
            'progress': 26
        }
        LINE_COLOR = (150, 150, 150)

        img = Image.new('RGB', IMG_SIZE, (255, 255, 255))
        draw = ImageDraw.Draw(img)

        # 字体加载（需确保系统有这些字体）
        try:
            font_path = 'msyh.ttc'
            fonts = {
                'header': ImageFont.truetype(font_path, FONT_CONFIG['header']),
                'content': ImageFont.truetype(font_path,
                                              FONT_CONFIG['content']),
                'amount': ImageFont.truetype(font_path, FONT_CONFIG['amount']),
                'progress': ImageFont.truetype(font_path,
                                               FONT_CONFIG['progress'])
            }
        except:
            fonts = {
                k: ImageFont.load_default().font_variant(size=v)
                for k, v in FONT_CONFIG.items()
            }

        # ============== 绘制逻辑 ==============
        def draw_separator(y):
            draw.line([(MARGIN, y), (IMG_SIZE[0] - MARGIN, y)],
                      fill=LINE_COLOR,
                      width=2)

        # 顶部区域
        title = f"{filename_data['identifier']} {filename_data['content']}"
        title_w = draw.textlength(title, font=fonts['header'])
        draw.text(((IMG_SIZE[0] - title_w) // 2, 50),
                  title,
                  fill=(0, 0, 0),
                  font=fonts['header'])

        subtitle = f"{filename_data['amount']} YUAN  {filename_data['quantity']} Zhang "
        subtitle_w = draw.textlength(subtitle, font=fonts['header'])
        draw.text(((IMG_SIZE[0] - subtitle_w) // 2, 110),
                  subtitle,
                  fill=(0, 0, 0),
                  font=fonts['header'])
        draw_separator(160)

        # 场次内容
        y = 200
        parts = line.split('|')
        selections = parts[1].split(',')

        for sel in selections:
            if match := re.match(r'(\d+)=(.+)', sel.strip()):
                match_num, choices = match.groups()
                # 场次显示格式
                base_text = f"[{match_num}] : "
                base_width = draw.textlength(base_text, font=fonts['content'])

                # 绘制场次编号
                draw.text((MARGIN, y),
                          base_text,
                          fill=(0, 0, 0),
                          font=fonts['content'])

                # 选项换行处理
                option_x = MARGIN + base_width + 20
                max_width = IMG_SIZE[0] - option_x - MARGIN
                lines = []
                current_line = []
                current_width = 0

                for char in choices.replace('/', '/'):
                    char_width = draw.textlength(char, font=fonts['content'])
                    if current_width + char_width > max_width:
                        lines.append(''.join(current_line))
                        current_line = [char]
                        current_width = char_width
                    else:
                        current_line.append(char)
                        current_width += char_width
                if current_line:
                    lines.append(''.join(current_line))

                # 绘制选项
                line_height = int(fonts['content'].size * 1.5)
                for i, line in enumerate(lines):
                    draw.text((option_x, y + i * line_height),
                              line,
                              fill=(0, 0, 0),
                              font=fonts['content'])

                y += line_height * len(lines) + 40

        # 底部区域
        draw_separator(y + 20)

        # 金额计算
        calculated_amount = BettingCalculator.calculate({
            'bet_code':
            parts[0],
            'fields': {
                s.split('=')[0]: s.split('=')[1].split('/')
                for s in selections
            },
            'base_multiplier': {
                'base': 2
            },
            'final_multiplier':
            int(parts[3])
        })

        # 绘制金额和进度
        amount_text = f"{calculated_amount}Yuan"
        amount_w = draw.textlength(amount_text, font=fonts['amount'])
        draw.text(((IMG_SIZE[0] - amount_w) // 2, y + 50),
                  amount_text,
                  fill=(0, 0, 0),
                  font=fonts['amount'])

        progress_text = f"{index+1}/{total}"
        progress_w = draw.textlength(progress_text, font=fonts['progress'])
        draw.text((IMG_SIZE[0] - MARGIN - progress_w, y + 50),
                  progress_text,
                  fill=(150, 150, 150),
                  font=fonts['progress'])

        # 输出图片
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format='PNG', quality=95)
        return img_byte_arr.getvalue()

    except Exception as e:
        raise ValueError(f"图片生成失败: {str(e)}")


# ==================== 投注计算扩展模块 ====================
class BettingCalculator:
    _calculators = {}

    @classmethod
    def register(cls, bet_type):

        def decorator(func):
            cls._calculators[bet_type.upper()] = func
            return func

        return decorator

    @classmethod
    def calculate(cls, data):
        calculator = cls._calculators.get(data['bet_code'].upper())
        if not calculator:
            raise ValueError(f"不支持的玩法类型: {data['bet_code']}")
        return calculator(data)


# 已支持的玩法类型
@BettingCalculator.register('SPF')  # 胜平负
@BettingCalculator.register('BQC')  # 半全场
@BettingCalculator.register('CBF')  # 比分
@BettingCalculator.register('SF')  # 胜负
@BettingCalculator.register('JQS')  # 总进球
@BettingCalculator.register('SXP')  # 上下盘
def default_calculator(data):
    """通用计算逻辑（胜平负/半全场/比分/胜负/总进球/上下盘）"""
    product = 1
    for field in data['fields'].values():
        product *= len(field)
    return data['base_multiplier']['base'] * product * data['final_multiplier']
