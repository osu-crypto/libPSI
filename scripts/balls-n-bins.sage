# Pr[ m balls between  n bins has max load B]
def prob(m,n,B, minSec):
    #print m,n,B

    sum = 0.0
    sec = 0#minSec + 1
    diff = 1
    i = B + 1
    #for i in range(B+1,B+1000):
    while diff > 0.000001:
        #print i
        sum = sum +n * binomial(m,i) * (1.0/n)^i *(1-1/n)^(m-i)
        #print "sum[",i,"] ", sum
        sec2  = (log(sum)/log(2.0)) * 1.0
        diff =abs( sec -sec2)
        sec = sec2
        i = i + 1
        #print i , sec
    return sec
# returns bin size for m bins and n balls to achieve sec-level sec
def getBinSize(m, n, sec):

    B =max(1,int( m / n))
    pp = 0
    step = 1


    doublingMode = true

    while pp > sec or step > 1:

        #pp = prob(m,n,B, -sec)

        #print "for N=2^",p," B=",B,"  sec=", pp
        if sec < pp:
            if doublingMode:
                step =  step * 2
                B = B + step
                #print "doubling B to ",B, "(",step,")"
            else:
                step = max(1,step / 2)
                B = B + step
                #print "incrementing B to", B," (",step,")"
        else:
            doublingMode  = false
            step =  max(1,step / 2)
            B = B - step
            #print "decrementing B to", B," (",step,")"
        #    print "m=",p," B=",B," ", pp

        #B = B + 1
        pp = prob(m,n,B, -sec)
    #print "m=",p," B=",B," ", pp
    return B


for p in [12, 16, 20, 24]:
    # num hash functions
    h = 3
    # num balls
    m = 2.0^p * h
    # num bins
    #n = 2.0^13
    n = 2* m / p

    sec1 = - 5
    sec2 = - 40

    n1 = getBinSize(m,n,sec1)
    n2 = getBinSize(m, n/2, sec1)
    n3 = getBinSize(m, n, sec2)
    n4 = getBinSize(m, n/2, sec2)

    #print "m=",p," e1=", m / n
    #print "m=",p," e2=", m / (n/2)
    #print "m=",p," n1=",n1, "  ", sec1
    #print "m=",p," n2=",n2, "  ", sec1
    #print "m=",p," n3=",n3, "  ", sec2
    #print "m=",p," n4=",n4, "  ", sec2
    print "base ",n3 * 2
    print "new  ",2 * n1 + 2*(n3-n2)

