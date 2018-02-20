package net.meeusen.concurrency;

/* shows simple threads usage
*/

/**
 * this thread class just increments its counter continuously (unless max reached)
 * */
class MyThread extends Thread {
    private Long counter=new Long(0);
    // user agrees to not call getCounter while Thread is running.
    public long getCounter() {
        return counter.longValue();
    }
    public void run() {
        while(! Thread.currentThread().isInterrupted()) {
            if ( 0!=counter.compareTo(Long.MAX_VALUE)) {
                counter++;    
            }            
        }
    }
}


public class ThreadsTest {
    
    MyThread[] AllMyThreads;
    public ThreadsTest(int NrThrds) {
        AllMyThreads = new MyThread[NrThrds];
        for ( int i=0; i<AllMyThreads.length; i++) {
            AllMyThreads[i] = new MyThread();            
        }
    }

    public void startThem() {
        for ( int i=0; i<AllMyThreads.length; i++) {            
            AllMyThreads[i].start();
        }
    }
    
    public void stopThem() throws InterruptedException {
        for ( int i=0; i<AllMyThreads.length; i++) {
            AllMyThreads[i].interrupt();
        }
        // just to be sure: 
        for ( int i=0; i<AllMyThreads.length; i++) {
            AllMyThreads[i].join();
        }
    }
    
    public void printTheirCounters() {
        for ( int i=0; i<AllMyThreads.length; i++) {
            System.out.println("Thrd " + i + " cntr: " + AllMyThreads[i].getCounter());
        }        
    }

    public static void main(String[] args) throws InterruptedException {
        int NrOfTestThreads = 44;
        System.out.println("Simple Java threads example.");
        ThreadsTest mytest = new ThreadsTest(NrOfTestThreads);

        mytest.startThem();        
        System.out.println("Started " + NrOfTestThreads + " test threads.");
        
        System.out.println("Now sleeping main thread.");        
        Thread.sleep(50);       
        
        System.out.println("Will now interrupt all the test threads.");
        mytest.stopThem();
        
        System.out.println("Printing counters.");
        mytest.printTheirCounters();
        
    }

}
