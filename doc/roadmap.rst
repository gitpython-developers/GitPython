=====================
What's next in: 0.2.0
=====================
 1. **Docs Review**
  * all documentation strings must be reviewed for resT correctness. Additionally they should be adjusted to use the sphinx fields like ":param:" and ":return:".
 2. **Review git-python's ability to parse the progress information sent when fetching and pushing**
  * Up to git 1.6.5, a push would still send progress. Then up to git 1.7.0 it will not produce progress to non-ttys anymore, making git-pythons test fail. Now git is implementing new --progress flags which would allow to enforce the sending of progress messages. This needs to be researched, implementation needs adjustments to assure we get the best possible progress results with git 1.6x as well as with git 1.7x.
 
=====================
What's next in: 0.2.1
=====================
 1. **Research possibility to read the object database ( including packs and alternates support ) directly.** 
  * Sample code can be found in dulwich, but it will have to be adjusted to perform better through configurable caching. Currently git-python can retrieve the data of about 10k smallish objects / s, the python implementation shouldn't be much slower than that. 
