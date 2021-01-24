# -*- coding: utf-8 -*-
import tensorflow as tf
#import matplotlib.pyplot as plt
import numpy as np
import datetime
from sklearn.metrics import roc_auc_score


def graph_embed(X, msg_mask, N_x, N_embed, N_o, iter_level, Wnode, Wembed, W_output, b_output):
    #X -- affine(W1) -- ReLU -- (Message -- affine(W2) -- add (with aff W1)
    # -- ReLU -- )* MessageAll  --  output
    node_val = tf.reshape(tf.matmul( tf.reshape(X, [-1, N_x]) , Wnode), #reshape 改变张量（tensor）的形状。
            [tf.shape(X)[0], -1, N_embed])                          #matmul 将矩阵 a 乘以矩阵 b,生成a * b
                                                            #tf.shape是用来获取张量的维度(shape)
    cur_msg = tf.nn.relu(node_val)   #[batch, node_num, embed_dim]  #计算激活函数 relu
    for t in range(iter_level):
        #Message convey
        Li_t = tf.matmul(msg_mask, cur_msg)  #[batch, node_num, embed_dim]      #矩阵乘法
        #Complex Function
        cur_info = tf.reshape(Li_t, [-1, N_embed])
        for Wi in Wembed:
            if (Wi == Wembed[-1]):  #最后一个
                cur_info = tf.matmul(cur_info, Wi)
            else:
                cur_info = tf.nn.relu(tf.matmul(cur_info, Wi))
        neigh_val_t = tf.reshape(cur_info, tf.shape(Li_t))
        #Adding
        tot_val_t = node_val + neigh_val_t
        #Nonlinearity
        tot_msg_t = tf.nn.tanh(tot_val_t)
        cur_msg = tot_msg_t   #[batch, node_num, embed_dim]

    g_embed = tf.reduce_sum(cur_msg, 1)   #[batch, embed_dim]  #用于计算张量tensor沿着某一维度的和，可以在求和后降维。
    output = tf.matmul(g_embed, W_output) + b_output
    
    return output


class graphnn(object):
    def __init__(self,
                    N_x,
                    Dtype, 
                    N_embed,
                    depth_embed,
                    N_o,
                    ITER_LEVEL,
                    lr,
                    device = '/gpu:0'
                ):

        self.NODE_LABEL_DIM = N_x

        #tf.reset_default_graph()        #清除默认图形堆栈并重置全局默认图形。
        tf.compat.v1.reset_default_graph()
        with tf.device(device):
            Wnode = tf.Variable(tf.random.truncated_normal(        #图变量的初始化方法
                                                            #截断的产生正态分布的随机数，即随机数与均值的差值若大于两倍的标准差，则重新生成
                shape = [N_x, N_embed], stddev = 0.1, dtype = Dtype)) 
            Wembed = []
            for i in range(depth_embed):
                Wembed.append(tf.Variable(tf.random.truncated_normal(
                    shape = [N_embed, N_embed], stddev = 0.1, dtype = Dtype)))

            W_output = tf.Variable(tf.random.truncated_normal(
                shape = [N_embed, N_o], stddev = 0.1, dtype = Dtype))
            b_output = tf.Variable(tf.constant(0, shape = [N_o], dtype = Dtype))    #tf.constant创建常量
            
            X1 = tf.compat.v1.placeholder(Dtype, [None, None, N_x]) #[B, N_node, N_x] #tf.compat.v1.placeholder()函数作为一种占位符用于定义过程，可以理解为形参，在执行的时候再赋具体的值。
            msg1_mask = tf.compat.v1.placeholder(Dtype, [None, None, None])
                                            #[B, N_node, N_node]
            self.X1 = X1
            self.msg1_mask = msg1_mask
            embed1 = graph_embed(X1, msg1_mask, N_x, N_embed, N_o, ITER_LEVEL,
                    Wnode, Wembed, W_output, b_output)  #[B, N_x]
            
            X2 = tf.compat.v1.placeholder(Dtype, [None, None, N_x])
            msg2_mask = tf.compat.v1.placeholder(Dtype, [None, None, None])
            self.X2 = X2
            self.msg2_mask = msg2_mask
            embed2 = graph_embed(X2, msg2_mask, N_x, N_embed, N_o, ITER_LEVEL,
                    Wnode, Wembed, W_output, b_output)

            label = tf.compat.v1.placeholder(Dtype, [None, ]) #same: 1; different:-1
            self.label = label
            self.embed1 = embed1

            
            cos = tf.reduce_sum(embed1*embed2, 1) / tf.sqrt(tf.reduce_sum(
                embed1**2, 1) * tf.reduce_sum(embed2**2, 1) + 1e-10)        #1e-10防止分母出现0

            diff = -cos
            self.diff = diff
            loss = tf.reduce_mean( (diff + label) ** 2 )    #计算跨张量维度的元素的均值。
            self.loss = loss
            #print("loss")
            #print(loss)
            #optimizer = tf.train.AdamOptimizer(learning_rate=lr).minimize(loss)
            optimizer = tf.compat.v1.train.AdamOptimizer(learning_rate=lr).minimize(loss)
            self.optimizer = optimizer
    
    def say(self, string):
        print (string)
        if self.log_file != None:
            self.log_file.write(string+'\n')
    
    def init(self, LOAD_PATH, LOG_PATH):
        #config = tf.ConfigProto()   #配置tf.Session的运算方式，比如gpu运算或者cpu运算
        config = tf.compat.v1.ConfigProto()
        config.gpu_options.allow_growth = True  #Tensorflow运行自动慢慢达到最大GPU的内存
        #sess = tf.Session(config=config)
        sess = tf.compat.v1.Session(config=config)
        #saver = tf.train.Saver()    #实例化一个Saver对象
        saver = tf.compat.v1.train.Saver(max_to_keep=25)
        self.sess = sess
        self.saver = saver
        self.log_file = None
        if (LOAD_PATH is not None):
            if LOAD_PATH == '#LATEST#':
                checkpoint_path = tf.train.latest_checkpoint('./')  #查找最新保存的checkpoint文件的文件名
            else:
                checkpoint_path = LOAD_PATH
            saver.restore(sess, checkpoint_path)    #恢复保存的模型
            if LOG_PATH != None:
                self.log_file = open(LOG_PATH, 'a+')
            self.say('{}, model loaded from file: {}'.format(
                datetime.datetime.now(), checkpoint_path))
        else:
            sess.run(tf.compat.v1.global_variables_initializer()) #global_variable_initializer则是开始执行每个variable里的initializer.
            if LOG_PATH != None:
                self.log_file = open(LOG_PATH, 'w')
            self.say('Training start @ {}'.format(datetime.datetime.now()))
    
    def get_embed(self, X1, mask1):
        vec, = self.sess.run(fetches=[self.embed1],
                feed_dict={self.X1:X1, self.msg1_mask:mask1})
        return vec

    def calc_loss(self, X1, X2, mask1, mask2, y):
        cur_loss, = self.sess.run(fetches=[self.loss], feed_dict={self.X1:X1,
            self.X2:X2,self.msg1_mask:mask1,self.msg2_mask:mask2,self.label:y})
        return cur_loss
        
    def calc_diff(self, X1, X2, mask1, mask2):
        diff, = self.sess.run(fetches=[self.diff], feed_dict={self.X1:X1,
            self.X2:X2, self.msg1_mask:mask1, self.msg2_mask:mask2})
        return diff
    
    def train(self, X1, X2, mask1, mask2, y):
        loss,_ = self.sess.run([self.loss,self.optimizer],feed_dict={self.X1:X1,
            self.X2:X2,self.msg1_mask:mask1,self.msg2_mask:mask2,self.label:y})
        return loss
    
    def save(self, path, epoch=None):
        checkpoint_path = self.saver.save(self.sess, path, global_step=epoch)
        return checkpoint_path
