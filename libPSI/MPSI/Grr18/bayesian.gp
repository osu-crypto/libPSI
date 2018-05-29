default(realprecision, 100);
default(parisizemax, 800000000);

bdist(n,k,p)    = 0.0+binomial(n,k)*(p^k)*(1-p)^(n-k);
bdistleq(n,k,p) = sum(i=0,k, 0.0 + bdist(n,i,p));
log2(x)         = log(x)/log(2);
overflowprob(n,m,B) = m * (1- bdistleq(n,B,1/m));
lappdf(x, eps) = (eps/2)*exp(-abs(x)*eps);
\\n = 2^16;  \\ number of items
\\m = n/4;   \\ number of bins

err = 1/(2^40);  \\ acceptable overall error probability
binerror = err/m ; \\implied acceptable error probability per bin
stop = 120; \\ignore bin sizes above this
prior = listcreate(stop);
for (z=0, stop+1, listput(prior, bdist(n, z, 1/m)))
prior;
remainingprobprint(dist) =
{
    a = 1;
    for(i=1, stop+1, a = a - dist[i]; print(i-1 " " a))
    for(i=1, stop+1, a = a - dist[i]; print(i-1 " " a))
    for(i=1, stop+1, a = a - dist[i]; print(i-1 " " a))
};
remainingprob(dist) =
{
    a = 1;
    out = listcreate(stop);
    for(i=1, stop+1, a = a - dist[i]; listput(out, a));
    return(out)
};
\\ remainingprob(prior)
postat(prior, evid, eps, x) =   
\\returns the posterior likelihood of a given real bin size
{
    total = 0;  \\total = total probability of seeing estimate evid
    for(i=0, stop+1, total = total + prior[i+1]*lappdf(abs(evid-i),eps));
    new = prior[x+1] * lappdf(abs(evid-x),eps) / total;
    \\print("total " total);
    \\print("pdf " lappdf(abs(evid-x),eps));
    return(new)
};
p = listcreate(stop);
for (z=0, stop+1, listput(p, postat(prior, estimate, 1, z)) );
posterior(prior, estimate, eps) =
\\ calculates a posterior distribution when 'estimate' is the private bin size estimate
{
    post = listcreate(stop);
    for (z=0, stop+1, listput(post, postat(prior, estimate, eps, z)) );
    return(post)
};
binsneeded(dist) =
{
    flag = 1;
    a = 1;
    bin = 0;
    while(a>binerror, 
        a = a-dist[bin+1];
        bin++ 
    );
    return(bin-1);
};
\\binsneeded(prior)  \\testing
createtable(mina, maxa, inc, prior, eps) =  \\exclusive of 'max' value
{
    est = mina;
    print("n = " n);
    print("m = " m);
    print("epsilon = " eps);
    print("error probability = " err);
    print("If estimated bin size is ____ then pad with dummies up to _____");

    write1("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18/output.txt","Lookup{" n ", " floor(m) ", " eps ", " mina ", {");
    while(est < maxa,
        post = posterior(prior, est, eps);
        needed = binsneeded(post);
        print(est ", " needed);
        write1("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18/output.txt", needed);
        est = est + inc;
        if(est < maxa,
            write1("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18/output.txt", ", ");
        );
    );

    write("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18//output.txt", "}},");
};
createtable(-10, 50, 1, prior, eps);


\\quit