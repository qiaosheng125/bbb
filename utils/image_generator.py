#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据处理模块 (原图像生成模块)

用于处理和计算投注数据。
注意：图片生成功能已移除，仅保留投注计算逻辑。
"""

class BettingCalculator:
    """投注计算工具，处理投注数据并计算结果"""
    
    _calculators = {}
    
    @classmethod
    def register(cls, bet_type):
        """注册计算器函数"""
        def decorator(func):
            cls._calculators[bet_type.upper()] = func
            return func
        return decorator
    
    @classmethod
    def calculate(cls, data):
        """
        计算投注金额
        
        参数:
            data: 包含投注数据的字典
                {
                    'bet_code': 投注类型代码,
                    'fields': {场次号: [选项列表]},
                    'base_multiplier': {'base': 基础倍数},
                    'final_multiplier': 最终倍数
                }
                
        返回:
            计算后的金额
        """
        calculator = cls._calculators.get(data['bet_code'].upper())
        if not calculator:
            raise ValueError(f"不支持的玩法类型: {data['bet_code']}")
        return calculator(data)
    
    @staticmethod
    def parse_data(text_content):
        """
        解析文本内容，提取投注数据
        
        参数:
            text_content: 包含投注数据的文本行
            
        返回:
            解析后的投注数据字典
        """
        # 简单的文本解析示例
        parts = text_content.strip().split('|')
        result = {}
        
        if len(parts) >= 1:
            result['content'] = parts[0].strip()
        
        if len(parts) >= 2:
            try:
                result['amount'] = float(parts[1].strip())
            except ValueError:
                result['amount'] = 0
                
        return result

# 注册支持的投注类型
@BettingCalculator.register('SPF')  # 胜平负
@BettingCalculator.register('BQC')  # 半全场
@BettingCalculator.register('CBF')  # 比分
@BettingCalculator.register('SF')   # 胜负
@BettingCalculator.register('JQS')  # 总进球
@BettingCalculator.register('SXP')  # 上下盘
def default_calculator(data):
    """通用计算逻辑（胜平负/半全场/比分/胜负/总进球/上下盘）"""
    product = 1
    for field in data['fields'].values():
        product *= len(field)
    return data['base_multiplier']['base'] * product * data['final_multiplier']

# 图片生成功能已移除