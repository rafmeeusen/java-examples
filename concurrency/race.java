/* shows race condition
   by letting multiple threads do read-modify-write on unprotected data
   i.e. : the expected number of increments doesn't match actual number of increments of the common data
   to fix the race condition: uncomment synchronized
   WARNING: the fix is NOT taking into account good coding practices
   see e.g. "private lock object idiom"
   (Joshua Bloch, Effective Java: Programming Language Guide, Addison-Wesley Professional, Boston, 2001.)
 */

class Data
{
    private int data = 0;
    public void set (int newvalue)
    {
        data = newvalue;
    }
    public int get ()
    {
        return data;
    }
}

/* thread class that increments given Data object a given number of times
   and then exits */
class DataIncrementer extends Thread
{
    private Data d;
    private int nrIncrementsLeft;

    DataIncrementer (Data d, int num)
    {
        this.d = d;
        this.nrIncrementsLeft = num;
    };

    public void run ()
    {
//    System.out.println( this.getName() + " started to do " + nrIncrementsLeft + " increments.");
        while (nrIncrementsLeft > 0)
        {
            //synchronized(d) {
            d.set (1 + d.get ());
            //}
            nrIncrementsLeft--;
        }
//    System.out.println( this.getName() + " exiting.");
    }
}


class Main
{

    public static void main (String[]args)
    {
        int nrIncThreads = 13;
        int nrIncsPerThread = 300;
        if (args.length == 2)
        {
            nrIncThreads = Integer.parseInt (args[0]);
            nrIncsPerThread = Integer.parseInt (args[1]);
        }
        System.out.println ("Race condition test with " + nrIncThreads +
                            " threads, each thread doing " + nrIncsPerThread +
                            " read-mod-writes.");
        Data singleDataObject = new Data ();

        DataIncrementer[]thds = new DataIncrementer[nrIncThreads];
        for (int i = 0; i < thds.length; i++)
        {
            thds[i] = new DataIncrementer (singleDataObject, nrIncsPerThread);
        }
        for (DataIncrementer thd:thds)
        {
            thd.start ();
        }

        System.out.println ("Main: waiting for threads to finish.");

        for (DataIncrementer thd:thds)
        {
            try
            {
                thd.join ();
            }
            catch (Exception e)
            {
            }
        }

        int expectedDataValue = nrIncThreads * nrIncsPerThread;
        System.out.println ("Main: expected data value: " + expectedDataValue);
        System.out.println ("Main: actual data value: " +
                            singleDataObject.get ());
        System.out.println ("Main: exiting.");
    }

}
